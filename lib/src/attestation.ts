import * as x509 from "@peculiar/x509";
import { cborDecode, cborEncodeArray, cborEncodeBytes, cborEncodeText } from "./cbor.js";
import { AWS_NITRO_ROOT_PEM } from "./nitroRoot.js";
import { base64ToBytes, bytesToHex, constTimeEq } from "./encoding.js";

export interface AttestationDoc {
  module_id: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  public_key?: Uint8Array;
  user_data?: Uint8Array;
  nonce?: Uint8Array;
}

export interface VerifiedAttestation {
  doc: AttestationDoc;
  pcr0Hex: string;
  attestationPubkeyHex: string;
}

const APP_KEY_PREFIX = "sha256:";
const APP_KEY_SEP = ";";
const PREFIX_LEN = APP_KEY_PREFIX.length; // 7
const HASH_LEN = 32;
const TLS_END = PREFIX_LEN + HASH_LEN; // 39
const SEP_END = TLS_END + APP_KEY_SEP.length; // 40
const APP_PREFIX_END = SEP_END + PREFIX_LEN; // 47
const APP_KEY_END = APP_PREFIX_END + HASH_LEN; // 79

/** Verify the attestation document against the AWS Nitro root and pinned PCR0. */
export async function verifyAttestation(input: {
  /** raw bytes of the COSE_Sign1 attestation document (NOT base64) */
  cose: Uint8Array;
  /** nonce we sent in the request, hex-encoded */
  expectedNonceHex: string;
  /** attestation pubkey from /v1/enclave-info, hex */
  attestationPubkeyHex: string;
  /** time used for chain expiry checks */
  now?: Date;
}): Promise<VerifiedAttestation> {
  const sign1 = cborDecode(input.cose);
  if (!Array.isArray(sign1) || sign1.length !== 4) {
    throw new Error("attestation: not a COSE_Sign1 array");
  }
  const protectedBytes = sign1[0] as Uint8Array;
  const payloadBytes = sign1[2] as Uint8Array;
  const signature = sign1[3] as Uint8Array;
  if (!(protectedBytes instanceof Uint8Array) || !(payloadBytes instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
    throw new Error("attestation: malformed COSE_Sign1 fields");
  }

  const doc = parseDoc(payloadBytes);

  // 1. Cert chain: cabundle[0] must chain to AWS Nitro root; doc.certificate is leaf.
  // Pass Uint8Array directly via BufferSource cast — peculiar/x509 accepts
  // BufferSource at runtime, but TS's `Uint8Array<ArrayBufferLike>` doesn't
  // structurally match its `AsnEncodedType` overload. The older
  // `new ArrayBuffer + .set()` wrapper triggered "Unsupported format of 'raw'
  // argument" in Node when the view came out of cbor-decode.
  const leaf = new x509.X509Certificate(doc.certificate as BufferSource);
  const intermediates = doc.cabundle.map((b) => new x509.X509Certificate(b as BufferSource));
  const root = new x509.X509Certificate(AWS_NITRO_ROOT_PEM);
  await verifyCertChain(leaf, intermediates, root, input.now ?? new Date());

  // 2. COSE_Sign1 signature: leaf cert pubkey verifies over Sig_structure.
  const sigStructure = cborEncodeArray([
    cborEncodeText("Signature1"),
    cborEncodeBytes(protectedBytes),
    cborEncodeBytes(new Uint8Array(0)),
    cborEncodeBytes(payloadBytes),
  ]);
  const ok = await verifyEcdsaP384(leaf, signature, sigStructure);
  if (!ok) throw new Error("attestation: COSE signature failed");

  // 3. Nonce.
  if (!doc.nonce) throw new Error("attestation: missing nonce");
  const expected = hexToBytesLocal(input.expectedNonceHex);
  if (!constTimeEq(doc.nonce, expected)) throw new Error("attestation: nonce mismatch");

  // 4. PCR0 must exist; client compares against published reference out-of-band.
  const pcr0 = doc.pcrs.get(0);
  if (!pcr0) throw new Error("attestation: missing PCR0");
  const pcr0Hex = bytesToHex(pcr0);

  // 5. appKeyHash binding: SHA256(attestationPubkey) == userData[47:79].
  if (!doc.user_data) throw new Error("attestation: missing user_data");
  if (doc.user_data.length < APP_KEY_END) throw new Error("attestation: user_data too short");
  const ud = doc.user_data;
  if (asciiSlice(ud, 0, PREFIX_LEN) !== APP_KEY_PREFIX) {
    throw new Error("attestation: user_data missing 'sha256:' at offset 0");
  }
  if (asciiSlice(ud, TLS_END, SEP_END) !== APP_KEY_SEP) {
    throw new Error("attestation: user_data missing ';' separator");
  }
  if (asciiSlice(ud, SEP_END, APP_PREFIX_END) !== APP_KEY_PREFIX) {
    throw new Error("attestation: user_data missing 'sha256:' at app offset");
  }
  const appKeyHash = ud.subarray(APP_PREFIX_END, APP_KEY_END);
  if (appKeyHash.every((b) => b === 0)) {
    throw new Error("attestation: appKeyHash is all zeros (key not registered)");
  }
  const pubkeyBytes = hexToBytesLocal(input.attestationPubkeyHex);
  const expectedHash = new Uint8Array(await crypto.subtle.digest("SHA-256", pubkeyBytes as BufferSource));
  if (!constTimeEq(expectedHash, appKeyHash)) {
    throw new Error(
      `attestation: appKeyHash mismatch — got ${bytesToHex(appKeyHash)}, expected SHA256(pubkey) = ${bytesToHex(expectedHash)}`,
    );
  }

  return { doc, pcr0Hex, attestationPubkeyHex: input.attestationPubkeyHex };
}

function parseDoc(payload: Uint8Array): AttestationDoc {
  const m = cborDecode(payload);
  if (!(m instanceof Map)) throw new Error("attestation: doc is not a CBOR map");
  const get = <T>(k: string): T | undefined => m.get(k) as T | undefined;
  const required = <T>(k: string): T => {
    const v = get<T>(k);
    if (v === undefined) throw new Error(`attestation: missing ${k}`);
    return v;
  };
  const pcrsRaw = required<Map<unknown, unknown>>("pcrs");
  const pcrs = new Map<number, Uint8Array>();
  for (const [k, v] of pcrsRaw.entries()) {
    if (typeof k !== "number" || !(v instanceof Uint8Array)) continue;
    pcrs.set(k, v);
  }
  const cabundleRaw = required<unknown[]>("cabundle");
  const cabundle: Uint8Array[] = [];
  for (const c of cabundleRaw) {
    if (c instanceof Uint8Array) cabundle.push(c);
  }
  const doc: AttestationDoc = {
    module_id: required<string>("module_id"),
    digest: required<string>("digest"),
    timestamp: required<number>("timestamp"),
    pcrs,
    certificate: required<Uint8Array>("certificate"),
    cabundle,
  };
  const pk = get<Uint8Array>("public_key"); if (pk) doc.public_key = pk;
  const ud = get<Uint8Array>("user_data"); if (ud) doc.user_data = ud;
  const nonce = get<Uint8Array>("nonce"); if (nonce) doc.nonce = nonce;
  return doc;
}

async function verifyCertChain(
  leaf: x509.X509Certificate,
  intermediates: x509.X509Certificate[],
  root: x509.X509Certificate,
  now: Date,
): Promise<void> {
  const chain = new x509.X509ChainBuilder({ certificates: [...intermediates, root] });
  const built = await chain.build(leaf);
  if (built.length === 0) throw new Error("attestation: empty cert chain");
  const last = built[built.length - 1];
  if (!last) throw new Error("attestation: empty chain");
  if (!constTimeEq(new Uint8Array(last.rawData), new Uint8Array(root.rawData))) {
    throw new Error("attestation: chain does not anchor to AWS Nitro root");
  }
  for (const cert of built) {
    if (now < cert.notBefore) throw new Error(`attestation: cert ${cert.subject} not yet valid`);
    if (now > cert.notAfter) throw new Error(`attestation: cert ${cert.subject} expired`);
  }
  for (let i = 0; i < built.length - 1; i++) {
    const child = built[i] as x509.X509Certificate;
    const parent = built[i + 1] as x509.X509Certificate;
    const verified = await child.verify({ publicKey: await parent.publicKey.export() });
    if (!verified) throw new Error(`attestation: signature on ${child.subject} invalid`);
  }
}

async function verifyEcdsaP384(
  leaf: x509.X509Certificate,
  rawSignature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  const pubkey = await crypto.subtle.importKey(
    "spki",
    leaf.publicKey.rawData as BufferSource,
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-384" },
    pubkey,
    rawSignature as BufferSource,
    message as BufferSource,
  );
}

function asciiSlice(buf: Uint8Array, start: number, end: number): string {
  let s = "";
  for (let i = start; i < end; i++) s += String.fromCharCode(buf[i] as number);
  return s;
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(view.byteLength);
  new Uint8Array(out).set(view);
  return out;
}

function hexToBytesLocal(hex: string): Uint8Array {
  if (hex.length % 2) throw new Error("hex: odd length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Convenience: decode the base64 doc returned by /enclave/attestation. */
export function decodeAttestationDocB64(b64OrJson: string): Uint8Array {
  const trimmed = b64OrJson.trim();
  let docB64 = trimmed;
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as { document?: string };
      if (parsed.document) docB64 = parsed.document;
    } catch {
      // fall through to base64 decode of original
    }
  }
  return base64ToBytes(docB64);
}

import type { ApiInfo } from "@e2ee-kv/protocol";

export async function fetchPcr0(runtimeBaseUrl: string): Promise<string> {
  // /enclave/attestation returns a base64-encoded COSE Sign1 doc. We extract
  // PCR0 by parsing it. Simple approach: ask for a fixed nonce, decode the doc
  // payload (CBOR), and pull out pcrs[0].
  const res = await fetch(`${runtimeBaseUrl}/enclave/attestation?nonce=0000000000000000`);
  if (!res.ok) throw new Error(`attestation fetch -> ${res.status}`);
  const docB64 = (await res.text()).trim();
  const doc = Buffer.from(docB64, "base64");
  // Decode COSE_Sign1 -> [protected, unprotected, payload, signature]
  // Then payload is CBOR map containing "pcrs" -> map<int, bytes>.
  return parsePcr0(doc);
}

function parsePcr0(doc: Buffer): string {
  // Minimal CBOR parser sufficient for COSE_Sign1 + the inner attestation map.
  const cur = { o: 0, b: doc };
  const arr = readCbor(cur);
  if (!Array.isArray(arr) || arr.length !== 4) throw new Error("not COSE_Sign1");
  const payloadBytes = arr[2] as Buffer;
  const payloadCur = { o: 0, b: payloadBytes };
  const payload = readCbor(payloadCur) as Map<unknown, unknown>;
  const pcrs = payload.get("pcrs") as Map<number, Buffer> | undefined;
  if (!pcrs) throw new Error("no pcrs in attestation");
  const pcr0 = pcrs.get(0);
  if (!pcr0) throw new Error("no pcr0");
  return Buffer.from(pcr0).toString("hex");
}

interface Cur { o: number; b: Buffer }

function readCbor(c: Cur): unknown {
  const ib = c.b[c.o++];
  if (ib === undefined) throw new Error("cbor: eof");
  const major = ib >> 5;
  const minor = ib & 0x1f;
  const len = readLen(c, minor);
  switch (major) {
    case 0: return len;
    case 1: return -1 - Number(len);
    case 2: { const buf = c.b.subarray(c.o, c.o + Number(len)); c.o += Number(len); return Buffer.from(buf); }
    case 3: { const s = c.b.subarray(c.o, c.o + Number(len)).toString("utf8"); c.o += Number(len); return s; }
    case 4: { const arr: unknown[] = []; for (let i = 0; i < Number(len); i++) arr.push(readCbor(c)); return arr; }
    case 5: { const m = new Map<unknown, unknown>(); for (let i = 0; i < Number(len); i++) { const k = readCbor(c); const v = readCbor(c); m.set(k, v); } return m; }
    case 6: return readCbor(c); // tag — pass through
    case 7: {
      if (minor === 20) return false;
      if (minor === 21) return true;
      if (minor === 22) return null;
      if (minor === 23) return undefined;
      throw new Error(`cbor: simple ${minor} unsupported`);
    }
    default: throw new Error(`cbor: major ${major} unsupported`);
  }
}

function readLen(c: Cur, minor: number): number | bigint {
  if (minor < 24) return minor;
  if (minor === 24) { const v = c.b[c.o]; if (v === undefined) throw new Error("cbor: eof"); c.o += 1; return v; }
  if (minor === 25) { const v = c.b.readUInt16BE(c.o); c.o += 2; return v; }
  if (minor === 26) { const v = c.b.readUInt32BE(c.o); c.o += 4; return v; }
  if (minor === 27) { const v = c.b.readBigUInt64BE(c.o); c.o += 8; return v; }
  throw new Error(`cbor: minor ${minor} unsupported`);
}

export function buildApiInfo(input: {
  pcr0: string;
  version: string;
  rp: { id: string; name: string; origin: string };
}): ApiInfo {
  return {
    pcr0: input.pcr0,
    version: input.version,
    providers: ["webauthn"],
    rp: input.rp,
  };
}

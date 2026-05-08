// Test fixture, NOT a product. Loaded by Playwright via a host-side static
// server. Attaches a runFlow() function on window that drives a full
// register → assert (with PRF) → encrypt → kv.put → kv.get → decrypt path
// against the live enclave at `baseUrl`. Returns enough state for the
// Playwright driver to perform the host-side opacity check.
import { fetchEnclaveInfo, RpcClient } from "@enclave-sdk/browser";
import { startRegistration, startAuthentication } from "@simplewebauthn/browser";

interface RunFlowOpts {
  baseUrl: string;
  expectedPcr0?: string;
  /** Plaintext to round-trip through put/get to prove E2EE works end to end. */
  plaintext?: string;
  /** User-supplied key name (the bit that becomes opaque key_id on the wire). */
  keyName?: string;
}

interface RunFlowResult {
  userId: string;
  credentialId: string;
  pcr0: string;
  attestationPubkeyHex: string;
  /** Plaintext recovered from kv.get — must match opts.plaintext. */
  recoveredPlaintext: string;
  /** key_id we used (base32, 32 chars). The host opacity check fetches this from /v1/storage. */
  keyId: string;
}

const PRF_SALT_INPUT = "enclave-kv-v1";

declare global {
  interface Window {
    runFlow: (opts: RunFlowOpts) => Promise<RunFlowResult>;
    flowError?: string;
  }
}

const log = document.getElementById("log") as HTMLPreElement;
function append(line: string) {
  log.textContent = (log.textContent ?? "") + "\n" + line;
}

async function hkdfSha256(ikm: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const salt = new Uint8Array(0);
  const baseKey = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: new TextEncoder().encode(info) },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

async function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as BufferSource }, k, plaintext as BufferSource),
  );
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

async function aesGcmDecrypt(key: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["decrypt"]);
  const nonce = blob.slice(0, 12);
  const ct = blob.slice(12);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce as BufferSource },
    k,
    ct as BufferSource,
  );
  return new Uint8Array(pt);
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as BufferSource));
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | (bytes[i] as number);
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function b64UrlToBytes(b64url: string): Uint8Array {
  const pad = (4 - (b64url.length % 4)) % 4;
  return b64ToBytes(b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad));
}

async function runFlow(opts: RunFlowOpts): Promise<RunFlowResult> {
  const plaintext = opts.plaintext ?? "regtest-secret-value";
  const keyName = opts.keyName ?? "regtest-key";

  append(`runFlow: baseUrl=${opts.baseUrl}`);

  // 1. Verify attestation chain end-to-end against the live enclave.
  // QEMU's NSM stub doesn't produce an AWS-Nitro-rooted cert chain, so
  // `fetchAndVerify` (full attestation chain) can't pass in the regtest
  // environment — only on real hardware. For the regtest harness we
  // pin to the attestation pubkey directly from /v1/enclave-info; the
  // RpcClient still Schnorr-verifies every response against that pubkey,
  // which is what actually matters for the JSON-RPC trust path.
  const info = await fetchEnclaveInfo(opts.baseUrl);
  if (!info.attestation_pubkey) throw new Error("enclave reports no attestation_pubkey");
  append(`pinned attestation_pubkey=${info.attestation_pubkey.slice(0, 16)}…`);

  // 2. JSON-RPC client pinned to the attestation pubkey. Every
  //    response is Schnorr-verified by RpcClient.
  let authToken: string | null = null;
  const rpc = new RpcClient({
    baseUrl: opts.baseUrl,
    attestationPubkeyHex: info.attestation_pubkey,
    authToken: () => authToken,
  });

  // 3. Register a passkey. The CDP virtual authenticator (set up by
  //    browser.mjs before this script runs) handles navigator.credentials.create()
  //    automatically because automaticPresenceSimulation is on.
  const beginReg = await rpc.call<{ server_nonce: string; options: unknown }>(
    "auth.webauthn.register.begin",
    {},
  );
  const credential = await startRegistration({ optionsJSON: beginReg.options as never });
  const finishReg = await rpc.call<{
    user_id: string;
    credential_id: string;
    auth_token: string;
    expires_at: number;
  }>("auth.webauthn.register.finish", {
    server_nonce: beginReg.server_nonce,
    credential,
  });
  authToken = finishReg.auth_token;
  append(`registered user_id=${finishReg.user_id}`);

  // 4. Assert with PRF — derive value_key, path_key from PRF output.
  const beginAssert = await rpc.call<{ server_nonce: string; options: any }>(
    "auth.webauthn.assert.begin",
    { user_id: finishReg.user_id },
  );
  // The fixed app salt — known to both ends; never crosses the wire.
  const prfSalt = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PRF_SALT_INPUT)),
  );
  // Inject the salt client-side. We use the existing harness assert pattern:
  // browser SDK passes options.extensions through to navigator.credentials.get()
  // unchanged, so a Uint8Array `eval.first` reaches WebAuthn as a BufferSource.
  beginAssert.options.extensions = {
    ...(beginAssert.options.extensions ?? {}),
    prf: { eval: { first: prfSalt } },
  };
  const assertion: any = await startAuthentication({ optionsJSON: beginAssert.options });
  const prfFirst = (() => {
    const r = assertion.clientExtensionResults?.prf?.results?.first;
    if (!r) throw new Error("authenticator did not return PRF output — not E2EE-capable");
    if (typeof r === "string") return b64UrlToBytes(r);
    return new Uint8Array(r);
  })();
  await rpc.call("auth.webauthn.assert.finish", {
    server_nonce: beginAssert.server_nonce,
    credential: assertion,
  });
  const valueKey = await hkdfSha256(prfFirst, "kv-v1-value-key");
  const pathKey = await hkdfSha256(prfFirst, "kv-v1-path-key");
  append(`derived keys (32B each)`);

  // 5. key_id = base32(HMAC(path_key, name)) truncated to 20 bytes (32 base32 chars).
  const macFull = await hmacSha256(pathKey, new TextEncoder().encode(keyName));
  const keyId = base32Encode(macFull.slice(0, 20));

  // Encrypt value + name (so the server can list display names without seeing them).
  const valueBlob = await aesGcmEncrypt(valueKey, new TextEncoder().encode(plaintext));
  const nameCtBlob = await aesGcmEncrypt(valueKey, new TextEncoder().encode(keyName));

  await rpc.call("kv.put", {
    key_id: keyId,
    value: bytesToB64(valueBlob),
    name_ct: bytesToB64(nameCtBlob),
    expected_version: 0,
  });
  append(`kv.put key_id=${keyId} ok`);

  // 6. Read back, decrypt, return.
  const got = await rpc.call<{ value: string; name_ct: string; version: number }>("kv.get", {
    key_id: keyId,
  });
  const recoveredBytes = await aesGcmDecrypt(valueKey, b64ToBytes(got.value));
  const recoveredPlaintext = new TextDecoder().decode(recoveredBytes);
  append(`kv.get → "${recoveredPlaintext}"`);

  return {
    userId: finishReg.user_id,
    credentialId: finishReg.credential_id,
    pcr0: "",  // QEMU's NSM stub — no usable PCR0 in regtest
    attestationPubkeyHex: info.attestation_pubkey,
    recoveredPlaintext,
    keyId,
  };
}

window.runFlow = async (opts) => {
  try {
    return await runFlow(opts);
  } catch (err) {
    window.flowError = (err as Error).message ?? String(err);
    append(`ERROR: ${window.flowError}`);
    throw err;
  }
};

append("ready");

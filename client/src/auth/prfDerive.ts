import { hkdfSha256 } from "../crypto/hkdf.js";

export const PRF_SALT = await crypto.subtle
  .digest("SHA-256", new TextEncoder().encode("enclave-kv-v1"))
  .then((buf) => new Uint8Array(buf));

export interface DerivedKeys {
  valueKey: Uint8Array;   // 32 bytes — AES-256 GCM
  pathKey: Uint8Array;    // 32 bytes — HMAC-SHA256
}

export async function derive(prfFirst: Uint8Array): Promise<DerivedKeys> {
  if (prfFirst.length !== 32) {
    throw new Error(`PRF output must be 32 bytes, got ${prfFirst.length}`);
  }
  const salt = new Uint8Array(0);
  const valueKey = await hkdfSha256(prfFirst, salt, "kv-v1-value-key", 32);
  const pathKey = await hkdfSha256(prfFirst, salt, "kv-v1-path-key", 32);
  return { valueKey, pathKey };
}

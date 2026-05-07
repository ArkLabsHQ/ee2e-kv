import { importAesKey, aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aesgcm.js";
import { importHmacKey, hmacSha256 } from "../crypto/hmac.js";
import { base32Encode } from "../crypto/base32.js";
import { base64ToBytes, bytesToBase64 } from "@enclave-sdk/browser";
import { derive } from "./prfDerive.js";

export interface AuthSession {
  userId: string;
  authToken: string;
  expiresAt: number;
}

let session: AuthSession | null = null;
let valueKey: CryptoKey | null = null;
let pathKey: CryptoKey | null = null;

export function getSession(): AuthSession | null { return session; }
export function getAuthToken(): string | null { return session?.authToken ?? null; }
export function isAuthed(): boolean { return session !== null && session.expiresAt > Date.now(); }

export async function setFromAssertion(input: {
  userId: string;
  authToken: string;
  expiresAt: number;
  prfFirst: Uint8Array;
}): Promise<void> {
  session = { userId: input.userId, authToken: input.authToken, expiresAt: input.expiresAt };
  const keys = await derive(input.prfFirst);
  valueKey = await importAesKey(keys.valueKey);
  pathKey = await importHmacKey(keys.pathKey);
}

export function clearSession(): void {
  session = null;
  valueKey = null;
  pathKey = null;
}

function requireKeys(): { v: CryptoKey; p: CryptoKey } {
  if (!valueKey || !pathKey) throw new Error("session: keys not derived (PRF-capable assertion required)");
  return { v: valueKey, p: pathKey };
}

/** key_id = base32(HMAC-SHA256(path_key, name)).slice(0, 32) — 20 bytes truncation. */
export async function deriveKeyId(name: string): Promise<string> {
  const { p } = requireKeys();
  const mac = await hmacSha256(p, new TextEncoder().encode(name));
  return base32Encode(mac.subarray(0, 20));
}

export async function encryptValue(plaintext: Uint8Array): Promise<string> {
  const { v } = requireKeys();
  return bytesToBase64(await aesGcmEncrypt(v, plaintext));
}

export async function decryptValue(packedB64: string): Promise<Uint8Array> {
  const { v } = requireKeys();
  return aesGcmDecrypt(v, base64ToBytes(packedB64));
}

export async function encryptName(name: string): Promise<string> {
  return encryptValue(new TextEncoder().encode(name));
}

export async function decryptName(nameCtB64: string): Promise<string> {
  const pt = await decryptValue(nameCtB64);
  return new TextDecoder().decode(pt);
}

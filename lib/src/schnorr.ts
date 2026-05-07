import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { hexToBytes } from "./encoding.js";

/**
 * Verify a BIP-340 Schnorr signature over SHA256(body) with a hex-encoded
 * compressed secp256k1 public key. Drops the prefix byte from compressed
 * (33-byte) keys to obtain the 32-byte x-only pubkey expected by BIP-340.
 */
export function verifySchnorrSignature(
  body: Uint8Array,
  sigHex: string,
  pubkeyHex: string,
): boolean {
  let pubkeyBytes = hexToBytes(pubkeyHex);
  if (pubkeyBytes.length === 33) pubkeyBytes = pubkeyBytes.subarray(1);
  if (pubkeyBytes.length !== 32) return false;
  const sig = hexToBytes(sigHex);
  if (sig.length !== 64) return false;
  const msg = sha256(body);
  return schnorr.verify(sig, msg, pubkeyBytes);
}

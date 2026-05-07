import { describe, expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { verifySchnorrSignature } from "./schnorr.js";
import { bytesToHex } from "./encoding.js";

describe("verifySchnorrSignature", () => {
  it("verifies a freshly-signed message", () => {
    const sk = schnorr.utils.randomPrivateKey();
    const xPub = schnorr.getPublicKey(sk);
    const compressed = new Uint8Array(33);
    compressed[0] = 0x02;
    compressed.set(xPub, 1);

    const body = new TextEncoder().encode("hello enclave");
    const msgHash = sha256(body);
    const sig = schnorr.sign(msgHash, sk);

    expect(verifySchnorrSignature(body, bytesToHex(sig), bytesToHex(compressed))).toBe(true);
  });

  it("rejects tampered body", () => {
    const sk = schnorr.utils.randomPrivateKey();
    const xPub = schnorr.getPublicKey(sk);
    const body = new TextEncoder().encode("a");
    const msgHash = sha256(body);
    const sig = schnorr.sign(msgHash, sk);
    expect(verifySchnorrSignature(new TextEncoder().encode("b"), bytesToHex(sig), bytesToHex(xPub))).toBe(false);
  });

  it("rejects malformed pubkey length", () => {
    expect(verifySchnorrSignature(new Uint8Array(0), "00".repeat(64), "00".repeat(10))).toBe(false);
  });
});

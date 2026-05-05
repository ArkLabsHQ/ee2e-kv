import { describe, expect, it } from "vitest";
import { aesGcmDecrypt, aesGcmEncrypt, importAesKey } from "./aesgcm.js";

describe("aes-gcm", () => {
  it("encrypt/decrypt round-trip", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await importAesKey(raw);
    const pt = new TextEncoder().encode("hello world");
    const packed = await aesGcmEncrypt(key, pt);
    const dec = await aesGcmDecrypt(key, packed);
    expect(new TextDecoder().decode(dec)).toBe("hello world");
  });

  it("rejects ciphertext under wrong key", async () => {
    const k1 = await importAesKey(crypto.getRandomValues(new Uint8Array(32)));
    const k2 = await importAesKey(crypto.getRandomValues(new Uint8Array(32)));
    const packed = await aesGcmEncrypt(k1, new TextEncoder().encode("x"));
    await expect(aesGcmDecrypt(k2, packed)).rejects.toThrow();
  });

  it("rejects truncated ciphertext", async () => {
    const k = await importAesKey(crypto.getRandomValues(new Uint8Array(32)));
    await expect(aesGcmDecrypt(k, new Uint8Array(10))).rejects.toThrow();
  });
});

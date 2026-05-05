export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number,
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    ikm as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: new TextEncoder().encode(info) as BufferSource,
    },
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}

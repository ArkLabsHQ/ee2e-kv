// RFC 4648 base32 (no padding).
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | (bytes[i] as number);
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

export function base32Decode(s: string): Uint8Array {
  const upper = s.toUpperCase();
  const out = new Uint8Array(Math.floor((upper.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let oi = 0;
  for (let i = 0; i < upper.length; i++) {
    const c = upper[i] as string;
    const idx = ALPHABET.indexOf(c);
    if (idx === -1) throw new Error(`base32: invalid char ${c}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out[oi++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out.subarray(0, oi);
}

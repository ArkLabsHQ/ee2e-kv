// Minimal CBOR decoder sufficient for COSE_Sign1 and Nitro attestation
// payloads. Returns typed values: numbers for ints, Uint8Array for bytes,
// string for text, arrays, Map for maps. No streaming, no tags-as-objects
// (tagged values pass through their inner value).

interface Cur { o: number; b: Uint8Array }

export function cborDecode(buf: Uint8Array): unknown {
  const c: Cur = { o: 0, b: buf };
  return readItem(c);
}

/** Sentinel returned by readItem when it consumes a CBOR break byte (0xff). */
const BREAK = Symbol("cbor:break");

function readItem(c: Cur): unknown {
  const ib = c.b[c.o++];
  if (ib === undefined) throw new Error("cbor: eof");
  const major = ib >> 5;
  const minor = ib & 0x1f;
  // Indefinite-length encoding: major 2/3/4/5 with minor 31 (followed by a
  // stream of items terminated by 0xff). Major 7 with minor 31 is the break
  // byte itself.
  if (minor === 31) {
    switch (major) {
      case 2: {
        const chunks: Uint8Array[] = [];
        for (;;) {
          const piece = readItem(c);
          if (piece === BREAK) break;
          if (!(piece instanceof Uint8Array)) throw new Error("cbor: indefinite bytes contains non-bytes");
          chunks.push(piece);
        }
        const total = chunks.reduce((s, p) => s + p.length, 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of chunks) { out.set(p, off); off += p.length; }
        return out;
      }
      case 3: {
        let s = "";
        for (;;) {
          const piece = readItem(c);
          if (piece === BREAK) break;
          if (typeof piece !== "string") throw new Error("cbor: indefinite text contains non-text");
          s += piece;
        }
        return s;
      }
      case 4: {
        const arr: unknown[] = [];
        for (;;) {
          const item = readItem(c);
          if (item === BREAK) break;
          arr.push(item);
        }
        return arr;
      }
      case 5: {
        const m = new Map<unknown, unknown>();
        for (;;) {
          const k = readItem(c);
          if (k === BREAK) break;
          const v = readItem(c);
          if (v === BREAK) throw new Error("cbor: break in map value position");
          m.set(k, v);
        }
        return m;
      }
      case 7: return BREAK;
      default: throw new Error(`cbor: indefinite-length not allowed for major ${major}`);
    }
  }
  const len = readLen(c, minor);
  const n = Number(len);
  switch (major) {
    case 0: return n;
    case 1: return -1 - n;
    case 2: { const out = c.b.subarray(c.o, c.o + n); c.o += n; return new Uint8Array(out); }
    case 3: { const out = new TextDecoder("utf-8").decode(c.b.subarray(c.o, c.o + n)); c.o += n; return out; }
    case 4: { const arr: unknown[] = []; for (let i = 0; i < n; i++) arr.push(readItem(c)); return arr; }
    case 5: { const m = new Map<unknown, unknown>(); for (let i = 0; i < n; i++) { const k = readItem(c); const v = readItem(c); m.set(k, v); } return m; }
    case 6: return readItem(c);
    case 7: {
      if (minor === 20) return false;
      if (minor === 21) return true;
      if (minor === 22) return null;
      if (minor === 23) return undefined;
      throw new Error(`cbor: unsupported simple ${minor}`);
    }
    default: throw new Error(`cbor: major ${major} unsupported`);
  }
}

function readLen(c: Cur, minor: number): number {
  if (minor < 24) return minor;
  if (minor === 24) {
    const v = c.b[c.o]; if (v === undefined) throw new Error("cbor: eof"); c.o += 1; return v;
  }
  if (minor === 25) {
    const v = (c.b[c.o] as number) << 8 | (c.b[c.o + 1] as number);
    c.o += 2; return v;
  }
  if (minor === 26) {
    const v = ((c.b[c.o] as number) << 24 | (c.b[c.o + 1] as number) << 16 | (c.b[c.o + 2] as number) << 8 | (c.b[c.o + 3] as number)) >>> 0;
    c.o += 4; return v;
  }
  if (minor === 27) {
    let v = 0;
    for (let i = 0; i < 8; i++) v = v * 256 + (c.b[c.o + i] as number);
    c.o += 8;
    if (v > Number.MAX_SAFE_INTEGER) throw new Error("cbor: length too large");
    return v;
  }
  throw new Error(`cbor: minor ${minor} unsupported`);
}

/** Encode a CBOR byte string header with the given content length, returns header bytes. */
export function cborByteStringHeader(length: number): Uint8Array {
  return cborHeader(2, length);
}

export function cborArrayHeader(length: number): Uint8Array {
  return cborHeader(4, length);
}

function cborHeader(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 65536) return new Uint8Array([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
  if (n < 0x100000000) return new Uint8Array([
    (major << 5) | 26,
    (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff,
  ]);
  throw new Error("cbor: length too large for header");
}

export function cborEncodeBytes(bytes: Uint8Array): Uint8Array {
  const h = cborByteStringHeader(bytes.length);
  const out = new Uint8Array(h.length + bytes.length);
  out.set(h, 0); out.set(bytes, h.length);
  return out;
}

export function cborEncodeArray(items: Uint8Array[]): Uint8Array {
  const h = cborArrayHeader(items.length);
  let total = h.length;
  for (const item of items) total += item.length;
  const out = new Uint8Array(total);
  out.set(h, 0);
  let off = h.length;
  for (const item of items) { out.set(item, off); off += item.length; }
  return out;
}

export function cborEncodeText(s: string): Uint8Array {
  const bytes = new TextEncoder().encode(s);
  const h = cborHeader(3, bytes.length);
  const out = new Uint8Array(h.length + bytes.length);
  out.set(h, 0); out.set(bytes, h.length);
  return out;
}

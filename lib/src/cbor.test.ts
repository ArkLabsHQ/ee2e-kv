import { describe, expect, it } from "vitest";
import { cborDecode } from "./cbor.js";

describe("cborDecode", () => {
  it("decodes definite-length map", () => {
    // a2 6161 01 6162 02  →  {"a":1, "b":2}
    const buf = new Uint8Array([0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]);
    const m = cborDecode(buf) as Map<unknown, unknown>;
    expect(m).toBeInstanceOf(Map);
    expect(m.get("a")).toBe(1);
    expect(m.get("b")).toBe(2);
  });

  it("decodes indefinite-length map (0xbf … 0xff)", () => {
    // bf 6161 01 6162 02 ff  →  {"a":1, "b":2}
    const buf = new Uint8Array([0xbf, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02, 0xff]);
    const m = cborDecode(buf) as Map<unknown, unknown>;
    expect(m).toBeInstanceOf(Map);
    expect(m.get("a")).toBe(1);
    expect(m.get("b")).toBe(2);
  });

  it("decodes indefinite-length array (0x9f … 0xff)", () => {
    // 9f 01 02 03 ff  →  [1,2,3]
    const buf = new Uint8Array([0x9f, 0x01, 0x02, 0x03, 0xff]);
    expect(cborDecode(buf)).toEqual([1, 2, 3]);
  });

  it("decodes indefinite-length byte string concatenation", () => {
    // 5f 42 aabb 41 cc ff  →  bytes(aabbcc)
    const buf = new Uint8Array([0x5f, 0x42, 0xaa, 0xbb, 0x41, 0xcc, 0xff]);
    const out = cborDecode(buf) as Uint8Array;
    expect(out).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
  });

  it("strips CBOR tag (major 6) and returns inner item", () => {
    // c1 1a deadbeef  →  tag(1, 0xdeadbeef)
    const buf = new Uint8Array([0xc1, 0x1a, 0xde, 0xad, 0xbe, 0xef]);
    expect(cborDecode(buf)).toBe(0xdeadbeef);
  });

  it("decodes nested indefinite map containing definite values (Nitro attestation shape)", () => {
    // bf 6b "module_id" 65 "abcde" 6c "certificate" 44 30820001 ff
    const buf = new Uint8Array([
      0xbf,
      0x69, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x69, 0x64, // "module_id"
      0x65, 0x61, 0x62, 0x63, 0x64, 0x65,                         // "abcde"
      0x6b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, // "certificate"
      0x44, 0x30, 0x82, 0x00, 0x01,                                // bytes 30 82 00 01
      0xff,
    ]);
    const m = cborDecode(buf) as Map<unknown, unknown>;
    expect(m.get("module_id")).toBe("abcde");
    const cert = m.get("certificate") as Uint8Array;
    expect(cert[0]).toBe(0x30);
  });
});

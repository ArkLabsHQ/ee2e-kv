import { describe, expect, it } from "vitest";
import { base32Encode, base32Decode } from "./base32.js";

describe("base32", () => {
  it("encodes RFC 4648 vectors", () => {
    expect(base32Encode(new TextEncoder().encode(""))).toBe("");
    expect(base32Encode(new TextEncoder().encode("f"))).toBe("MY");
    expect(base32Encode(new TextEncoder().encode("fo"))).toBe("MZXQ");
    expect(base32Encode(new TextEncoder().encode("foo"))).toBe("MZXW6");
    expect(base32Encode(new TextEncoder().encode("foobar"))).toBe("MZXW6YTBOI");
  });

  it("round-trips random bytes", () => {
    for (let len = 0; len < 64; len++) {
      const b = crypto.getRandomValues(new Uint8Array(len));
      const dec = base32Decode(base32Encode(b));
      expect(Array.from(dec)).toEqual(Array.from(b));
    }
  });
});

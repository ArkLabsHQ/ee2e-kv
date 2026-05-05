import { describe, expect, it } from "vitest";
import { SessionStore, bindChallenge } from "./sessions.js";

describe("SessionStore", () => {
  it("issues unique nonces", () => {
    const s = new SessionStore(64, 60_000);
    const a = s.begin().nonceB64;
    const b = s.begin().nonceB64;
    expect(a).not.toBe(b);
  });

  it("consume is single-use", () => {
    const s = new SessionStore(64, 60_000);
    const n = s.begin().nonceB64;
    expect(s.consume(n)).toBe(true);
    expect(s.consume(n)).toBe(false);
  });

  it("rejects unknown nonces", () => {
    const s = new SessionStore(64, 60_000);
    expect(s.consume("nope")).toBe(false);
  });

  it("expires nonces after TTL", async () => {
    const s = new SessionStore(64, 1);
    const n = s.begin().nonceB64;
    await new Promise((r) => setTimeout(r, 5));
    expect(s.consume(n)).toBe(false);
  });
});

describe("bindChallenge", () => {
  it("is deterministic for the same op+nonce", () => {
    const a = bindChallenge("register", "AAAA");
    const b = bindChallenge("register", "AAAA");
    expect(a).toBe(b);
  });

  it("differs by op", () => {
    expect(bindChallenge("register", "AAAA")).not.toBe(bindChallenge("assert", "AAAA"));
  });

  it("differs by nonce", () => {
    expect(bindChallenge("register", "AAAA")).not.toBe(bindChallenge("register", "BBBB"));
  });
});

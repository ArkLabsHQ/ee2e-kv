import { describe, expect, it } from "vitest";
import { TokenIssuer, TokenError } from "./jwt.js";

const KEY = new Uint8Array(32).fill(0x42);

describe("TokenIssuer", () => {
  it("issues and verifies a token", () => {
    const t = new TokenIssuer(KEY, 60_000);
    const out = t.issue("user1", "cred1");
    const claims = t.verify(out.token);
    expect(claims.user_id).toBe("user1");
    expect(claims.credential_id).toBe("cred1");
    expect(claims.jti).toBe(out.jti);
  });

  it("rejects tampered tokens", () => {
    const t = new TokenIssuer(KEY, 60_000);
    const tok = t.issue("user1", "cred1").token;
    const parts = tok.split(".");
    const tampered = `${parts[0]}.${parts[1]}.${"X".repeat((parts[2] as string).length)}`;
    expect(() => t.verify(tampered)).toThrow(TokenError);
  });

  it("rejects expired tokens", async () => {
    const t = new TokenIssuer(KEY, 1);
    const tok = t.issue("user1", "cred1").token;
    await new Promise((r) => setTimeout(r, 5));
    expect(() => t.verify(tok)).toThrow(/expired/);
  });

  it("rejects replay after consumeJti", () => {
    const t = new TokenIssuer(KEY, 60_000);
    const out = t.issue("user1", "cred1");
    expect(() => t.verify(out.token)).not.toThrow();
    t.consumeJti(out.jti);
    expect(() => t.verify(out.token)).toThrow(/replay/);
  });

  it("rejects tokens signed with a different key", () => {
    const t1 = new TokenIssuer(KEY, 60_000);
    const t2 = new TokenIssuer(new Uint8Array(32).fill(0x99), 60_000);
    const tok = t1.issue("u", "c").token;
    expect(() => t2.verify(tok)).toThrow(/bad signature/);
  });
});

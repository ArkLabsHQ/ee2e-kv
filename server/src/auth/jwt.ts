import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { TtlLru } from "../lru.js";

export interface AuthClaims {
  user_id: string;
  credential_id: string;
  jti: string;
  exp: number;
}

export class TokenIssuer {
  private readonly seenJti: TtlLru<string, true>;
  constructor(
    private readonly key: Uint8Array,
    private readonly ttlMs: number,
    jtiCacheSize = 4096,
  ) {
    this.seenJti = new TtlLru(jtiCacheSize, ttlMs + 60_000);
  }

  issue(userId: string, credentialId: string, jti?: string): { token: string; expiresAt: number; jti: string } {
    const exp = Math.floor((Date.now() + this.ttlMs) / 1000);
    const useJti = jti ?? randomBytes(16).toString("base64url");
    const claims: AuthClaims = { user_id: userId, credential_id: credentialId, jti: useJti, exp };
    const header = b64url(Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })));
    const payload = b64url(Buffer.from(JSON.stringify(claims)));
    const signingInput = `${header}.${payload}`;
    const sig = b64url(this.sign(Buffer.from(signingInput, "utf8")));
    return { token: `${signingInput}.${sig}`, expiresAt: exp * 1000, jti: useJti };
  }

  verify(token: string): AuthClaims {
    const parts = token.split(".");
    if (parts.length !== 3) throw new TokenError("malformed");
    const [h, p, s] = parts as [string, string, string];
    const expected = b64url(this.sign(Buffer.from(`${h}.${p}`, "utf8")));
    if (!constTimeEq(s, expected)) throw new TokenError("bad signature");
    let claims: AuthClaims;
    try {
      claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as AuthClaims;
    } catch {
      throw new TokenError("malformed payload");
    }
    if (typeof claims.exp !== "number" || claims.exp * 1000 <= Date.now()) {
      throw new TokenError("expired");
    }
    if (this.seenJti.has(claims.jti)) {
      throw new TokenError("replay");
    }
    return claims;
  }

  /** Mark a jti as consumed for replay protection on single-use operations. */
  consumeJti(jti: string): void {
    this.seenJti.set(jti, true);
  }

  private sign(data: Buffer): Buffer {
    const h = createHmac("sha256", this.key);
    h.update(data);
    return h.digest();
  }
}

export class TokenError extends Error {
  constructor(reason: string) {
    super(`token: ${reason}`);
    this.name = "TokenError";
  }
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function constTimeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

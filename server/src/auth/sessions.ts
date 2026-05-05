import { randomBytes, createHash } from "node:crypto";
import { TtlLru } from "../lru.js";

export interface ServerNonce {
  nonceB64: string;
  expiresAt: number;
}

export class SessionStore {
  private readonly store: TtlLru<string, true>;
  constructor(maxSize: number, private readonly ttlMs: number) {
    this.store = new TtlLru(maxSize, ttlMs);
  }

  begin(): ServerNonce {
    const buf = randomBytes(32);
    const nonceB64 = buf.toString("base64");
    this.store.set(nonceB64, true);
    return { nonceB64, expiresAt: Date.now() + this.ttlMs };
  }

  consume(nonceB64: string): boolean {
    return this.store.consume(nonceB64) === true;
  }
}

export function bindChallenge(op: string, serverNonceB64: string): string {
  const nonce = Buffer.from(serverNonceB64, "base64");
  const h = createHash("sha256");
  h.update(Buffer.from(`e2ee-kv|${op}|`, "utf8"));
  h.update(nonce);
  return h.digest("base64url");
}

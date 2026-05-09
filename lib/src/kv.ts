import { aesGcmDecrypt, aesGcmEncrypt, importAesKey } from "./crypto/aesgcm.js";
import { base32Encode } from "./crypto/base32.js";
import { hmacSha256, importHmacKey } from "./crypto/hmac.js";
import { base64ToBytes, bytesToBase64 } from "./encoding.js";
import { derive } from "./auth/prfDerive.js";
import { assert, register } from "./auth/webauthn.js";
import { RpcClient } from "./rpcClient.js";

export interface KvSession {
  userId: string;
  authToken: string;
  expiresAt: number;
}

export interface KvItem {
  name: string;
  keyId: string;
  version: number;
  updatedAt: number;
}

export interface KvGetResult {
  value: string;
  version: number;
  updatedAt: number;
}

export interface KvClientOpts {
  baseUrl?: string;
  /** Pin every response to this attestation pubkey (from /v1/enclave-info). Pass null to disable verification (dev only). */
  attestationPubkeyHex: string | null;
}

/**
 * High-level E2EE client for the enclave-e2ee-kv server.
 *
 * Wraps a {@link RpcClient} with the WebAuthn-PRF auth flow and the
 * client-side AES-GCM / HMAC plumbing. Once {@link register} or
 * {@link assert} has succeeded, {@link put}/{@link get}/{@link del}/
 * {@link list} take and return plaintext — encryption + key-id derivation
 * happen internally so the server only ever sees opaque ciphertext.
 */
export class KvClient {
  private readonly rpc: RpcClient;
  private session: KvSession | null = null;
  private valueKey: CryptoKey | null = null;
  private pathKey: CryptoKey | null = null;

  constructor(opts: KvClientOpts) {
    this.rpc = new RpcClient({
      ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
      attestationPubkeyHex: opts.attestationPubkeyHex,
      authToken: () => this.session?.authToken ?? null,
    });
  }

  getSession(): KvSession | null { return this.session; }
  isAuthed(): boolean { return this.session !== null && this.session.expiresAt > Date.now(); }

  /** Register a new passkey. Performs the follow-up assertion automatically so E2EE keys are derived. */
  async register(opts: { userHandle?: string } = {}): Promise<KvSession> {
    const reg = await register(this.rpc, opts);
    this.session = { userId: reg.userId, authToken: reg.authToken, expiresAt: reg.expiresAt };
    return this.assert({ userId: reg.userId });
  }

  /** Authenticate with an existing passkey + derive E2EE keys from PRF output. */
  async assert(opts: { userId?: string } = {}): Promise<KvSession> {
    const a = await assert(this.rpc, opts);
    if (!a.prfFirst) throw new Error("authenticator did not return PRF output — passkey is not E2EE-capable");
    this.session = { userId: a.userId, authToken: a.authToken, expiresAt: a.expiresAt };
    const keys = await derive(a.prfFirst);
    this.valueKey = await importAesKey(keys.valueKey);
    this.pathKey = await importHmacKey(keys.pathKey);
    return this.session;
  }

  logout(): void {
    this.session = null;
    this.valueKey = null;
    this.pathKey = null;
  }

  async put(name: string, value: string | Uint8Array, opts: { expectedVersion?: number } = {}): Promise<{ version: number }> {
    const { v } = this.requireKeys();
    const keyId = await this.deriveKeyId(name);
    const valueBytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
    const valueB64 = bytesToBase64(await aesGcmEncrypt(v, valueBytes));
    const nameCt = bytesToBase64(await aesGcmEncrypt(v, new TextEncoder().encode(name)));
    const expected = opts.expectedVersion ?? await this.currentVersion(keyId);
    const r = await this.rpc.call<{ version: number }>("kv.put", {
      key_id: keyId,
      value: valueB64,
      name_ct: nameCt,
      expected_version: expected,
    });
    return { version: r.version };
  }

  async get(name: string): Promise<KvGetResult | null> {
    const keyId = await this.deriveKeyId(name);
    let raw: { value: string; name_ct: string; version: number; updated_at: number };
    try {
      raw = await this.rpc.call("kv.get", { key_id: keyId });
    } catch (err) {
      const code = (err as { rpcError?: { code?: number } } | null)?.rpcError?.code;
      if (code === -32010) return null; // not_found
      throw err;
    }
    const { v } = this.requireKeys();
    const pt = await aesGcmDecrypt(v, base64ToBytes(raw.value));
    return { value: new TextDecoder().decode(pt), version: raw.version, updatedAt: raw.updated_at };
  }

  async del(name: string, expectedVersion: number): Promise<void> {
    const keyId = await this.deriveKeyId(name);
    await this.rpc.call("kv.del", { key_id: keyId, expected_version: expectedVersion });
  }

  async list(): Promise<KvItem[]> {
    const { v } = this.requireKeys();
    const out = await this.rpc.call<{ items: Array<{ key_id: string; name_ct: string; version: number; updated_at: number }> }>(
      "kv.list", {},
    );
    const result: KvItem[] = [];
    for (const it of out.items) {
      const nameBytes = await aesGcmDecrypt(v, base64ToBytes(it.name_ct));
      result.push({ name: new TextDecoder().decode(nameBytes), keyId: it.key_id, version: it.version, updatedAt: it.updated_at });
    }
    return result;
  }

  /** Direct access to the underlying RPC client (e.g. for non-KV methods like auth.credentials.list). */
  get rpcClient(): RpcClient { return this.rpc; }

  private requireKeys(): { v: CryptoKey; p: CryptoKey } {
    if (!this.valueKey || !this.pathKey) throw new Error("KvClient: not authenticated — call register() or assert() first");
    return { v: this.valueKey, p: this.pathKey };
  }

  private async deriveKeyId(name: string): Promise<string> {
    const { p } = this.requireKeys();
    const mac = await hmacSha256(p, new TextEncoder().encode(name));
    return base32Encode(mac.subarray(0, 20));
  }

  private async currentVersion(keyId: string): Promise<number> {
    try {
      const got = await this.rpc.call<{ version: number }>("kv.get", { key_id: keyId });
      return got.version;
    } catch {
      return 0;
    }
  }
}

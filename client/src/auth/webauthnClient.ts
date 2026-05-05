import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { RpcClient } from "../enclave/rpcClient.js";
import { PRF_SALT } from "./prfDerive.js";
import { base64ToBytes, bytesToBase64 } from "../crypto/encoding.js";

export interface RegisterResult {
  userId: string;
  credentialId: string;
  authToken: string;
  expiresAt: number;
}

export interface AssertResult {
  userId: string;
  authToken: string;
  expiresAt: number;
  prfFirst: Uint8Array | null;
}

interface RegisterBeginResult { server_nonce: string; options: unknown }
interface RegisterFinishResult { user_id: string; credential_id: string; auth_token: string; expires_at: number }
interface AssertBeginResult { server_nonce: string; options: unknown }
interface AssertFinishResult { user_id: string; auth_token: string; expires_at: number }

type Opts = { userHandle?: string };

export async function register(rpc: RpcClient, opts: Opts = {}): Promise<RegisterResult> {
  const params = opts.userHandle ? { user_handle: opts.userHandle } : {};
  const begin = await rpc.call<RegisterBeginResult>("auth.webauthn.register.begin", params);
  const opts_ = injectPrfOnRegister(begin.options);
  const credential = await startRegistration({ optionsJSON: opts_ as never });
  const finish = await rpc.call<RegisterFinishResult>("auth.webauthn.register.finish", {
    server_nonce: begin.server_nonce,
    credential,
  });
  return {
    userId: finish.user_id,
    credentialId: finish.credential_id,
    authToken: finish.auth_token,
    expiresAt: finish.expires_at,
  };
}

export async function assert(rpc: RpcClient, opts: { userId?: string } = {}): Promise<AssertResult> {
  const params = opts.userId ? { user_id: opts.userId } : {};
  const begin = await rpc.call<AssertBeginResult>("auth.webauthn.assert.begin", params);
  const opts_ = injectPrfOnAssert(begin.options);
  const credential = await startAuthentication({ optionsJSON: opts_ as never });
  const prfFirst = extractPrfFirst(credential);
  const finish = await rpc.call<AssertFinishResult>("auth.webauthn.assert.finish", {
    server_nonce: begin.server_nonce,
    credential,
  });
  return {
    userId: finish.user_id,
    authToken: finish.auth_token,
    expiresAt: finish.expires_at,
    prfFirst,
  };
}

function injectPrfOnRegister(options: unknown): unknown {
  // PublicKeyCredentialCreationOptionsJSON — extensions.prf to register
  const o = options as { extensions?: Record<string, unknown> };
  o.extensions = { ...(o.extensions ?? {}), prf: {} };
  return o;
}

function injectPrfOnAssert(options: unknown): unknown {
  const o = options as { extensions?: Record<string, unknown> };
  o.extensions = {
    ...(o.extensions ?? {}),
    prf: { eval: { first: bytesToBase64Url(PRF_SALT) } },
  };
  return o;
}

function extractPrfFirst(credential: unknown): Uint8Array | null {
  const c = credential as {
    clientExtensionResults?: { prf?: { results?: { first?: ArrayBuffer | string } } };
  };
  const first = c.clientExtensionResults?.prf?.results?.first;
  if (!first) return null;
  if (typeof first === "string") {
    // base64url
    return base64UrlToBytes(first);
  }
  return new Uint8Array(first);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return base64ToBytes(b64);
}

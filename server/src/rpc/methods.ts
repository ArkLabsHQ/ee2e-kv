import { ErrorCode, MethodSchemas, type Method } from "@e2ee-kv/protocol";
import type { Ctx } from "./context.js";
import { RpcAppError } from "./dispatcher.js";
import type { SessionStore } from "../auth/sessions.js";
import type { TokenIssuer } from "../auth/jwt.js";
import type { WebAuthnProvider } from "../auth/webauthn.js";
import { WebAuthnError } from "../auth/webauthn.js";
import type { KvService } from "../kv/handlers.js";
import { userKey } from "../storage/keys.js";
import type { StorageClient } from "../storage/client.js";

export interface MethodDeps {
  sessions: SessionStore;
  tokens: TokenIssuer;
  provider: WebAuthnProvider;
  kv: KvService;
  storage: StorageClient;
}

export type MethodHandler = (params: unknown, ctx: Ctx) => Promise<unknown>;

export function buildHandlers(deps: MethodDeps): Record<Method, MethodHandler> {
  return {
    "session.begin": async () => {
      const s = deps.sessions.begin();
      return { server_nonce: s.nonceB64, expires_at: s.expiresAt };
    },

    "auth.webauthn.register.begin": async (params, ctx) => {
      const p = MethodSchemas["auth.webauthn.register.begin"].params.parse(params);
      // If user_handle is given, must be authed AND match
      if (p.user_handle) {
        if (!ctx.auth) throw new RpcAppError(ErrorCode.unauthorized, "auth required to add credential");
        if (ctx.auth.user_id !== p.user_handle) {
          throw new RpcAppError(ErrorCode.forbidden, "user_handle mismatch");
        }
      }
      const r = await deps.provider.beginRegister(p.user_handle);
      return { server_nonce: r.serverNonce, options: r.options };
    },

    "auth.webauthn.register.finish": async (params) => {
      const p = MethodSchemas["auth.webauthn.register.finish"].params.parse(params);
      let result;
      try {
        result = await deps.provider.finishRegister(p.server_nonce, p.credential);
      } catch (e) {
        throw fromWebAuthn(e);
      }
      const session = deps.sessions.begin();
      const tok = deps.tokens.issue(result.userId, result.credentialId, session.nonceB64);
      return {
        user_id: result.userId,
        credential_id: result.credentialId,
        auth_token: tok.token,
        expires_at: tok.expiresAt,
      };
    },

    "auth.webauthn.assert.begin": async (params) => {
      const p = MethodSchemas["auth.webauthn.assert.begin"].params.parse(params);
      const r = await deps.provider.beginAssert(p.user_id);
      return { server_nonce: r.serverNonce, options: r.options };
    },

    "auth.webauthn.assert.finish": async (params) => {
      const p = MethodSchemas["auth.webauthn.assert.finish"].params.parse(params);
      let result;
      try {
        result = await deps.provider.verifyAssert(p.server_nonce, p.credential);
      } catch (e) {
        throw fromWebAuthn(e);
      }
      const session = deps.sessions.begin();
      const tok = deps.tokens.issue(result.userId, result.credentialId, session.nonceB64);
      return {
        user_id: result.userId,
        auth_token: tok.token,
        expires_at: tok.expiresAt,
      };
    },

    "auth.credentials.list": async (_params, ctx) => {
      const userId = requireAuth(ctx);
      const user = await deps.provider.loadUser(userId);
      const credentials = (user?.credentials ?? []).map((c) => {
        const item: { id: string; created_at: number; transports?: string[] } = {
          id: c.id,
          created_at: c.created_at,
        };
        if (c.transports) item.transports = c.transports;
        return item;
      });
      return { credentials };
    },

    "auth.credentials.delete": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["auth.credentials.delete"].params.parse(params);
      const user = await deps.provider.loadUser(userId);
      if (!user) throw new RpcAppError(ErrorCode.not_found, "user");
      const idx = user.credentials.findIndex((c) => c.id === p.credential_id);
      if (idx === -1) throw new RpcAppError(ErrorCode.not_found, "credential");
      if (user.credentials.length <= 1) {
        throw new RpcAppError(ErrorCode.forbidden, "cannot delete last credential");
      }
      user.credentials.splice(idx, 1);
      await deps.storage.put(userKey(userId), Buffer.from(JSON.stringify(user), "utf8"));
      // The credential index entry could be deleted here too — leaving it for a
      // dedicated hygiene pass since deletions are best-effort and cross-blob.
      return { ok: true as const };
    },

    "kv.get": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["kv.get"].params.parse(params);
      const rec = await deps.kv.get(userId, p.key_id);
      if (!rec) throw new RpcAppError(ErrorCode.not_found, "key");
      return { value: rec.value, name_ct: rec.name_ct, version: rec.version };
    },

    "kv.put": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["kv.put"].params.parse(params);
      const r = await deps.kv.put(userId, p.key_id, p.value, p.name_ct, p.expected_version);
      if (r.kind === "conflict") {
        throw new RpcAppError(ErrorCode.version_conflict, "version_conflict", { current_version: r.current_version });
      }
      return { new_version: r.new_version };
    },

    "kv.del": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["kv.del"].params.parse(params);
      const r = await deps.kv.del(userId, p.key_id, p.expected_version);
      if (r.kind === "not_found") throw new RpcAppError(ErrorCode.not_found, "key");
      if (r.kind === "conflict") {
        throw new RpcAppError(ErrorCode.version_conflict, "version_conflict", { current_version: r.current_version });
      }
      return { ok: true as const };
    },

    "kv.list": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["kv.list"].params.parse(params);
      const out = await deps.kv.list(userId, p.cursor, p.limit ?? 100);
      return out;
    },

    "kv.batch_get": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["kv.batch_get"].params.parse(params);
      const results: Record<string, unknown> = {};
      for (const id of p.key_ids) {
        const rec = await deps.kv.get(userId, id);
        results[id] = rec
          ? { value: rec.value, name_ct: rec.name_ct, version: rec.version }
          : { error: "not_found" as const };
      }
      return { results };
    },

    "kv.batch_put": async (params, ctx) => {
      const userId = requireAuth(ctx);
      const p = MethodSchemas["kv.batch_put"].params.parse(params);
      const results: unknown[] = [];
      for (const item of p.items) {
        const r = await deps.kv.put(userId, item.key_id, item.value, item.name_ct, item.expected_version);
        if (r.kind === "ok") {
          results.push({ new_version: r.new_version });
        } else {
          results.push({ error: "version_conflict", data: { current_version: r.current_version } });
        }
      }
      return { results };
    },
  };
}

function requireAuth(ctx: Ctx): string {
  if (!ctx.auth) throw new RpcAppError(ErrorCode.unauthorized, "auth required");
  return ctx.auth.user_id;
}

function fromWebAuthn(e: unknown): RpcAppError {
  if (e instanceof WebAuthnError) {
    if (e.reason === "nonce_invalid_or_used") {
      return new RpcAppError(ErrorCode.nonce_invalid_or_used, "nonce_invalid_or_used");
    }
    return new RpcAppError(ErrorCode.webauthn_failed, "webauthn_failed", { reason: e.reason });
  }
  return new RpcAppError(ErrorCode.internal_error, "internal_error");
}

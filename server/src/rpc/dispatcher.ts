import { z } from "zod";
import {
  ErrorCode,
  MethodSchemas,
  RpcRequest,
  type Method,
  type RpcResponse,
} from "@e2ee-kv/protocol";
import type { Ctx } from "./context.js";
import type { MethodHandler } from "./methods.js";
import type { TokenIssuer } from "../auth/jwt.js";
import { TokenError } from "../auth/jwt.js";
import { log } from "../log.js";

export class RpcAppError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
    this.name = "RpcAppError";
  }
}

export interface DispatcherDeps {
  tokens: TokenIssuer;
  handlers: Record<Method, MethodHandler>;
}

export async function dispatch(
  rawBody: unknown,
  authHeader: string | null,
  deps: DispatcherDeps,
): Promise<RpcResponse> {
  const reqResult = RpcRequest.safeParse(rawBody);
  if (!reqResult.success) {
    return errorResponse(null, ErrorCode.invalid_request, "invalid_request");
  }
  const req = reqResult.data;
  const id = req.id ?? null;
  const method = req.method as Method;

  const schema = MethodSchemas[method];
  if (!schema) return errorResponse(id, ErrorCode.method_not_found, `unknown method: ${method}`);

  const auth = authHeader ? parseBearer(authHeader) : null;
  let ctx: Ctx = { auth: null };
  if (auth) {
    try {
      ctx = { auth: deps.tokens.verify(auth) };
    } catch (e) {
      const reason = e instanceof TokenError ? e.message : "invalid token";
      return errorResponse(id, ErrorCode.unauthorized, reason);
    }
  }

  if (schema.auth === true && !ctx.auth) {
    return errorResponse(id, ErrorCode.unauthorized, "auth required");
  }

  const handler = deps.handlers[method];
  try {
    const result = await handler(req.params, ctx);
    return { jsonrpc: "2.0", id, result };
  } catch (e) {
    if (e instanceof RpcAppError) {
      const err: RpcResponse["error"] = e.data === undefined
        ? { code: e.code, message: e.message }
        : { code: e.code, message: e.message, data: e.data };
      return { jsonrpc: "2.0", id, error: err };
    }
    if (e instanceof z.ZodError) {
      return errorResponse(id, ErrorCode.invalid_params, "invalid_params", e.issues);
    }
    log.error("rpc handler crashed", { method, err: String(e) });
    return errorResponse(id, ErrorCode.internal_error, "internal_error");
  }
}

function errorResponse(
  id: RpcResponse["id"],
  code: number,
  message: string,
  data?: unknown,
): RpcResponse {
  const error: RpcResponse["error"] = data === undefined ? { code, message } : { code, message, data };
  return { jsonrpc: "2.0", id, error };
}

function parseBearer(header: string): string | null {
  const m = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return m && m[1] ? m[1] : null;
}

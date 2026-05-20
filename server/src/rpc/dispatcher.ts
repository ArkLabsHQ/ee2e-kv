import { z } from "zod";
import { SpanStatusCode } from "@opentelemetry/api";
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
import { tracer } from "../telemetry.js";
import { rpcRequests, rpcDuration, startTimer } from "../metrics.js";
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
  requestId: string,
  deps: DispatcherDeps,
): Promise<RpcResponse> {
  return tracer.startActiveSpan("rpc.dispatch", async (span) => {
    const elapsed = startTimer();
    span.setAttributes({
      "rpc.system": "jsonrpc",
      "rpc.jsonrpc.request_id": requestId,
      "rpc.jsonrpc.has_auth": authHeader != null,
    });

    // Single exit point: records the request counter + latency histogram with
    // the resolved (method, outcome) labels and ends the span.
    const finish = (method: string, outcome: string, response: RpcResponse): RpcResponse => {
      const labels = { rpc_method: method, outcome };
      rpcRequests.add(1, labels);
      rpcDuration.record(elapsed(), labels);
      span.end();
      return response;
    };

    const reqResult = RpcRequest.safeParse(rawBody);
    if (!reqResult.success) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: "invalid_request" });
      span.setAttribute("rpc.error_code", ErrorCode.invalid_request);
      return finish(
        "unknown",
        "invalid_request",
        errorResponse(null, ErrorCode.invalid_request, "invalid_request"),
      );
    }
    const req = reqResult.data;
    const id = req.id ?? null;
    const method = req.method as Method;
    span.setAttribute("rpc.method", method);

    const schema = MethodSchemas[method];
    if (!schema) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: "method_not_found" });
      span.setAttribute("rpc.error_code", ErrorCode.method_not_found);
      return finish(
        method,
        "method_not_found",
        errorResponse(id, ErrorCode.method_not_found, `unknown method: ${method}`),
      );
    }

    const auth = authHeader ? parseBearer(authHeader) : null;
    let ctx: Ctx = { auth: null };
    if (auth) {
      try {
        ctx = { auth: deps.tokens.verify(auth) };
      } catch (e) {
        const reason = e instanceof TokenError ? e.message : "invalid token";
        span.setStatus({ code: SpanStatusCode.ERROR, message: reason });
        span.setAttribute("rpc.error_code", ErrorCode.unauthorized);
        return finish(method, "unauthorized", errorResponse(id, ErrorCode.unauthorized, reason));
      }
    }

    if (ctx.auth) {
      span.setAttribute("user.id", ctx.auth.user_id);
      span.setAttribute("user.credential_id", ctx.auth.credential_id);
    }

    if (schema.auth === true && !ctx.auth) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: "auth required" });
      span.setAttribute("rpc.error_code", ErrorCode.unauthorized);
      return finish(
        method,
        "unauthorized",
        errorResponse(id, ErrorCode.unauthorized, "auth required"),
      );
    }

    const userId = ctx.auth?.user_id;
    const handler = deps.handlers[method];
    try {
      const result = await handler(req.params, ctx);
      span.setStatus({ code: SpanStatusCode.OK });
      log.info("rpc.ok", {
        method,
        outcome: "ok",
        duration_ms: Math.round(elapsed()),
        request_id: requestId,
        user_id: userId,
      });
      return finish(method, "ok", { jsonrpc: "2.0", id, result });
    } catch (e) {
      if (e instanceof RpcAppError) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: e.message });
        span.setAttribute("rpc.error_code", e.code);
        log.info("rpc.app_error", {
          method,
          code: e.code,
          message: e.message,
          request_id: requestId,
          user_id: userId,
        });
        const err: RpcResponse["error"] =
          e.data === undefined
            ? { code: e.code, message: e.message }
            : { code: e.code, message: e.message, data: e.data };
        return finish(method, "app_error", { jsonrpc: "2.0", id, error: err });
      }
      if (e instanceof z.ZodError) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: "invalid_params" });
        span.setAttribute("rpc.error_code", ErrorCode.invalid_params);
        log.warn("rpc.invalid_params", {
          method,
          request_id: requestId,
          paths: e.issues.map((i) => i.path.join(".")),
        });
        return finish(
          method,
          "invalid_params",
          errorResponse(id, ErrorCode.invalid_params, "invalid_params", e.issues),
        );
      }
      span.recordException(e as Error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: "internal_error" });
      span.setAttribute("rpc.error_code", ErrorCode.internal_error);
      log.error("rpc handler crashed", { method, request_id: requestId, err: String(e) });
      return finish(
        method,
        "internal_error",
        errorResponse(id, ErrorCode.internal_error, "internal_error"),
      );
    }
  });
}

function errorResponse(
  id: RpcResponse["id"],
  code: number,
  message: string,
  data?: unknown,
): RpcResponse {
  const error: RpcResponse["error"] =
    data === undefined ? { code, message } : { code, message, data };
  return { jsonrpc: "2.0", id, error };
}

function parseBearer(header: string): string | null {
  const m = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return m && m[1] ? m[1] : null;
}

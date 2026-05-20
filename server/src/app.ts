import { randomUUID } from "node:crypto";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { context, propagation, SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";
import type { Config } from "./config.js";
import type { ApiInfo } from "@e2ee-kv/protocol";
import { dispatch } from "./rpc/dispatcher.js";
import { buildHandlers, type MethodDeps } from "./rpc/methods.js";
import type { TokenIssuer } from "./auth/jwt.js";
import { tracer } from "./telemetry.js";
import { rpcRequests } from "./metrics.js";
import { log } from "./log.js";

export interface AppDeps extends MethodDeps {
  tokens: TokenIssuer;
  config: Config;
  apiInfo: ApiInfo;
}

// Per-request values stashed on the Hono context.
type AppEnv = { Variables: { requestId: string } };

export function createApp(deps: AppDeps): Hono<AppEnv> {
  const app = new Hono<AppEnv>();
  const handlers = buildHandlers(deps);

  // Telemetry middleware — registered before CORS so the span covers the
  // whole request, preflight included. Continues an upstream trace if the
  // caller sent W3C `traceparent`, otherwise starts a fresh one.
  app.use("/api/*", async (c, next) => {
    const parentCtx = propagation.extract(
      context.active(),
      Object.fromEntries(c.req.raw.headers),
    );
    const requestId = c.req.header("x-request-id") ?? randomUUID();
    c.set("requestId", requestId);

    await tracer.startActiveSpan(
      `${c.req.method} ${c.req.path}`,
      {
        kind: SpanKind.SERVER,
        attributes: {
          "http.request.method": c.req.method,
          "http.route": c.req.path,
          "request.id": requestId,
        },
      },
      parentCtx,
      async (span) => {
        try {
          await next();
          span.setAttribute("http.response.status_code", c.res.status);
          if (c.res.status >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
        } catch (err) {
          span.recordException(err as Error);
          span.setStatus({ code: SpanStatusCode.ERROR });
          throw err;
        } finally {
          span.end();
        }
      },
    );
  });

  // Cross-origin: real consumer webapps live at their own origin and call this
  // API directly. Allowlist is configured per-deployment via CORS_ALLOWED_ORIGINS
  // (comma-separated). Empty list ⇒ no cross-origin requests permitted.
  if (deps.config.corsAllowedOrigins.length > 0) {
    app.use(
      "/api/*",
      cors({
        origin: deps.config.corsAllowedOrigins,
        allowHeaders: ["authorization", "content-type"],
        allowMethods: ["GET", "POST", "OPTIONS"],
        maxAge: 600,
      }),
    );
  }

  app.get("/api/info", (c) => c.json(deps.apiInfo));

  app.post("/api/rpc", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      const span = trace.getActiveSpan();
      span?.recordException(new Error("parse_error"));
      span?.setStatus({ code: SpanStatusCode.ERROR });
      rpcRequests.add(1, { rpc_method: "unknown", outcome: "parse_error" });
      return c.json(
        { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse_error" } },
        400,
      );
    }
    const auth = c.req.header("authorization") ?? null;
    const res = await dispatch(body, auth, c.get("requestId"), {
      tokens: deps.tokens,
      handlers,
    });
    return c.json(res);
  });

  app.get("/healthz", (c) => c.text("ok"));

  app.notFound((c) => c.text("not_found", 404));
  app.onError((err, c) => {
    log.error("unhandled", { err: String(err) });
    return c.json({ error: "internal_error" }, 500);
  });

  return app;
}

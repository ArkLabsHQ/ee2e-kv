import { Hono } from "hono";
import type { Config } from "./config.js";
import type { ApiInfo } from "@e2ee-kv/protocol";
import { dispatch } from "./rpc/dispatcher.js";
import { buildHandlers, type MethodDeps } from "./rpc/methods.js";
import type { TokenIssuer } from "./auth/jwt.js";
import { staticHandler } from "./static.js";
import { log } from "./log.js";

export interface AppDeps extends MethodDeps {
  tokens: TokenIssuer;
  config: Config;
  apiInfo: ApiInfo;
}

export function createApp(deps: AppDeps): Hono {
  const app = new Hono();
  const handlers = buildHandlers(deps);

  app.get("/api/info", (c) => c.json(deps.apiInfo));

  app.post("/api/rpc", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse_error" } },
        400,
      );
    }
    const auth = c.req.header("authorization") ?? null;
    const res = await dispatch(body, auth, { tokens: deps.tokens, handlers });
    return c.json(res);
  });

  app.get("/healthz", (c) => c.text("ok"));

  app.use("*", staticHandler(deps.config.staticDir));

  app.notFound((c) => c.text("not_found", 404));
  app.onError((err, c) => {
    log.error("unhandled", { err: String(err) });
    return c.json({ error: "internal_error" }, 500);
  });

  return app;
}

import { serve } from "@hono/node-server";
import { loadConfig } from "./config.js";
import { HttpStorageClient } from "./storage/client.js";
import { SessionStore } from "./auth/sessions.js";
import { TokenIssuer } from "./auth/jwt.js";
import { WebAuthnProvider } from "./auth/webauthn.js";
import { KvService } from "./kv/handlers.js";
import { createApp } from "./app.js";
import { buildApiInfo } from "./info.js";
import { log } from "./log.js";

async function main(): Promise<void> {
  const config = loadConfig();
  log.info("e2ee-kv-server starting", { port: config.port, version: config.version });

  const storage = new HttpStorageClient(config.runtimeBaseUrl, config.runtimeToken);
  const sessions = new SessionStore(8192, config.sessionTtlMs);
  const tokens = new TokenIssuer(config.authTokenKey, config.authTokenTtlMs);
  const provider = new WebAuthnProvider(config.rp, storage, sessions);
  const kv = new KvService(storage);

  const apiInfo = buildApiInfo({ version: config.version, rp: config.rp });
  const app = createApp({ config, apiInfo, sessions, tokens, provider, kv, storage });

  serve({ fetch: app.fetch, port: config.port, hostname: "0.0.0.0" }, ({ port }) => {
    log.info("listening", { port });
  });
}

main().catch((err: unknown) => {
  log.error("fatal", { err: String(err) });
  process.exit(1);
});

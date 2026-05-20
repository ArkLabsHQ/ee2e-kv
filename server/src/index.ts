// Imported first so the OTEL providers are registered before any other
// module creates a tracer, meter, or logger handle.
import { shutdownTelemetry, telemetryEnabled, withSpan } from "./telemetry.js";
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
  await withSpan("e2ee-kv.startup", {}, async () => {
    const config = loadConfig();
    log.info("e2ee-kv-server starting", {
      port: config.port,
      version: config.version,
      telemetry: telemetryEnabled,
    });

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
  });
}

// Flush buffered telemetry before exiting so the final spans/logs are not lost.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    void shutdownTelemetry().finally(() => process.exit(0));
  });
}

main().catch((err: unknown) => {
  log.error("fatal", { err: String(err) });
  void shutdownTelemetry().finally(() => process.exit(1));
});

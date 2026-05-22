import { z } from "zod";

const Env = z.object({
  ENCLAVE_APP_PORT: z.string().regex(/^\d+$/).transform(Number).default("7074"),
  PORT: z.string().regex(/^\d+$/).transform(Number).optional(),
  ENCLAVE_RUNTIME_TOKEN: z.string().min(1, "ENCLAVE_RUNTIME_TOKEN required"),
  AUTH_TOKEN_KEY: z.string().regex(/^[0-9a-f]{64,}$/i, "AUTH_TOKEN_KEY must be hex (>=32 bytes)"),
  RP_ID: z.string().min(1).default("localhost"),
  RP_NAME: z.string().min(1).default("Enclave KV"),
  RP_ORIGIN: z.string().url().default("http://localhost:7074"),
  ENCLAVE_PROXY_PORT: z.string().regex(/^\d+$/).default("8080"),
  APP_VERSION: z.string().default("0.0.1"),
  SESSION_TTL_MS: z.string().regex(/^\d+$/).transform(Number).default(String(5 * 60_000)),
  AUTH_TOKEN_TTL_MS: z.string().regex(/^\d+$/).transform(Number).default(String(15 * 60_000)),
  CORS_ALLOWED_ORIGINS: z.string().default(""),
});

export interface Config {
  port: number;
  runtimeToken: string;
  authTokenKey: Uint8Array;
  rp: { id: string; name: string; origin: string };
  runtimeBaseUrl: string;
  version: string;
  sessionTtlMs: number;
  authTokenTtlMs: number;
  corsAllowedOrigins: string[];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = Env.parse(env);
  const port = parsed.PORT ?? parsed.ENCLAVE_APP_PORT;
  const authTokenKey = hexToBytes(parsed.AUTH_TOKEN_KEY);
  return {
    port,
    runtimeToken: parsed.ENCLAVE_RUNTIME_TOKEN,
    authTokenKey,
    rp: { id: parsed.RP_ID, name: parsed.RP_NAME, origin: parsed.RP_ORIGIN },
    runtimeBaseUrl: `http://127.0.0.1:${parsed.ENCLAVE_PROXY_PORT}`,
    version: parsed.APP_VERSION,
    sessionTtlMs: parsed.SESSION_TTL_MS,
    authTokenTtlMs: parsed.AUTH_TOKEN_TTL_MS,
    corsAllowedOrigins: parsed.CORS_ALLOWED_ORIGINS
      .split(",")
      .map((o) => o.trim())
      .filter((o) => o.length > 0),
  };
}

function hexToBytes(hex: string): Uint8Array {
  const len = hex.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

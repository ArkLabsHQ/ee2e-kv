import { readFile, stat } from "node:fs/promises";
import { join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Context, MiddlewareHandler } from "hono";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".webp": "image/webp",
  ".woff2": "font/woff2",
  ".ico": "image/x-icon",
  ".map": "application/json; charset=utf-8",
};

function ext(p: string): string {
  const i = p.lastIndexOf(".");
  return i === -1 ? "" : p.slice(i).toLowerCase();
}

export function staticHandler(rootDir: string): MiddlewareHandler {
  // Resolve relative to current working dir; in production /app/src is cwd.
  const here = fileURLToPath(new URL(".", import.meta.url));
  const root = resolve(here, rootDir.startsWith("/") ? rootDir : `../${rootDir}`);

  return async (c: Context, next) => {
    if (c.req.method !== "GET" && c.req.method !== "HEAD") return next();
    const url = new URL(c.req.url);
    let pathname = decodeURIComponent(url.pathname);
    if (pathname.endsWith("/")) pathname += "index.html";
    if (pathname === "" || pathname === "/") pathname = "/index.html";
    const safe = normalize(pathname).replace(/^\/+/, "");
    if (safe.startsWith("..")) return c.text("forbidden", 403);

    const filePath = join(root, safe);
    if (!filePath.startsWith(root)) return c.text("forbidden", 403);

    try {
      const s = await stat(filePath);
      if (!s.isFile()) return next();
      const body = await readFile(filePath);
      const type = MIME[ext(filePath)] ?? "application/octet-stream";
      return c.body(new Uint8Array(body), 200, { "content-type": type });
    } catch {
      // SPA fallback: serve index.html for non-API GETs that don't match a file.
      if (!safe.startsWith("api/") && !safe.startsWith("enclave/") && !safe.startsWith("v1/")) {
        try {
          const idx = await readFile(join(root, "index.html"));
          return c.body(new Uint8Array(idx), 200, { "content-type": "text/html; charset=utf-8" });
        } catch {
          // fall through
        }
      }
      return next();
    }
  };
}

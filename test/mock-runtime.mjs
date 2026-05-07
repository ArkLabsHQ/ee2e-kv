// Minimal stand-in for the framework supervisor: serves /v1/storage/* and a
// stub /enclave/attestation so the e2ee-kv server can boot end-to-end without
// a real Nitro enclave. In-memory only, NOT for production. Auth is checked
// against ENCLAVE_RUNTIME_TOKEN to mirror the real surface.

import { createServer } from "node:http";

const PORT = Number(process.env.MOCK_PORT ?? 7073);
const TOKEN = process.env.ENCLAVE_RUNTIME_TOKEN ?? "";
if (!TOKEN) {
  console.error("ENCLAVE_RUNTIME_TOKEN must be set");
  process.exit(1);
}

const store = new Map();

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const auth = req.headers.authorization ?? "";

  // Mock attestation: return JSON with a fake pcr0 so /api/info has something
  // recognisable. The real endpoint returns a base64 COSE_Sign1 — the server
  // catches the parse error and falls back to "unavailable" anyway, but we
  // give it valid JSON so logs stay clean.
  if (req.method === "GET" && url.pathname === "/enclave/attestation") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ pcr0: "mock-pcr0-deadbeef".padEnd(96, "0") }));
    return;
  }

  if (auth !== `Bearer ${TOKEN}`) {
    res.writeHead(401).end();
    return;
  }

  if (url.pathname === "/v1/storage" && req.method === "GET") {
    const prefix = url.searchParams.get("prefix") ?? "";
    const keys = [...store.keys()].filter((k) => k.startsWith(prefix));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(keys));
    return;
  }

  if (url.pathname.startsWith("/v1/storage/")) {
    const key = decodeURIComponent(url.pathname.slice("/v1/storage/".length));
    if (req.method === "GET") {
      const v = store.get(key);
      if (!v) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/octet-stream" }).end(v);
      return;
    }
    if (req.method === "PUT") {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      store.set(key, Buffer.concat(chunks));
      res.writeHead(204).end();
      return;
    }
    if (req.method === "DELETE") {
      store.delete(key);
      res.writeHead(204).end();
      return;
    }
  }

  res.writeHead(404).end();
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mock-runtime listening on http://127.0.0.1:${PORT}`);
});

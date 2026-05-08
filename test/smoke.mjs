#!/usr/bin/env node
// Node smoke client for the QEMU regtest. Imports @enclave-sdk/browser
// (the same SDK consumer webapps would use) and verifies the JSON-RPC API,
// attestation chain, Schnorr response signatures end-to-end against the
// live EIF.
//
// Output is bash-grep-friendly: `PASS: …` / `FAIL: …` for each step.
// Exit 0 if all pass, 1 otherwise.
import {
  fetchEnclaveInfo,
  fetchAndVerify,
  RpcClient,
} from "@enclave-sdk/browser";

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--base-url") out.baseUrl = argv[++i];
    else if (k === "--expected-pcr0") out.expectedPcr0 = argv[++i];
    else if (k === "--cors-origin") out.corsOrigin = argv[++i];
  }
  if (!out.baseUrl) {
    console.error("Usage: smoke.mjs --base-url <url> [--expected-pcr0 <hex>] [--cors-origin <url>]");
    process.exit(2);
  }
  return out;
}

let passed = 0, failed = 0;
function pass(label) { console.log(`  PASS: ${label}`); passed++; }
function fail(label, err) {
  console.log(`  FAIL: ${label} — ${err?.message ?? err}`);
  if (err?.stack) console.log(err.stack.split("\n").slice(1, 4).map((l) => `        ${l.trim()}`).join("\n"));
  failed++;
}
async function step(label, fn) {
  try { await fn(); pass(label); } catch (err) { fail(label, err); }
}

async function main() {
  const opts = parseArgs(process.argv);
  console.log(`smoke.mjs against ${opts.baseUrl}`);

  await step("GET /healthz returns 200 ok", async () => {
    const r = await fetch(`${opts.baseUrl}/healthz`);
    if (r.status !== 200) throw new Error(`status ${r.status}`);
    const t = await r.text();
    if (t.trim() !== "ok") throw new Error(`unexpected body: ${t}`);
  });

  await step("GET /api/info returns expected shape", async () => {
    const r = await fetch(`${opts.baseUrl}/api/info`);
    if (r.status !== 200) throw new Error(`status ${r.status}`);
    const j = await r.json();
    if (!j.version) throw new Error("missing version");
    if (!Array.isArray(j.providers) || !j.providers.includes("webauthn")) {
      throw new Error(`missing webauthn provider: ${JSON.stringify(j.providers)}`);
    }
    if (!j.rp?.id) throw new Error("missing rp.id");
  });

  let attestationPubkeyHex = null;
  await step("GET /v1/enclave-info returns attestation_pubkey", async () => {
    const info = await fetchEnclaveInfo(opts.baseUrl);
    if (!info.attestation_pubkey) throw new Error("attestation_pubkey missing");
    attestationPubkeyHex = info.attestation_pubkey;
  });

  await step("attestation chain verifies (Nitro CA → COSE → nonce → PCR0 → appKeyHash)", async () => {
    const verified = await fetchAndVerify(opts.baseUrl);
    if (!verified.pcr0Hex) throw new Error("no pcr0Hex returned");
    if (opts.expectedPcr0 && verified.pcr0Hex !== opts.expectedPcr0) {
      throw new Error(`pcr0 mismatch: got ${verified.pcr0Hex}, expected ${opts.expectedPcr0}`);
    }
    if (verified.attestationPubkeyHex !== attestationPubkeyHex) {
      throw new Error("attestation pubkey doesn't match /v1/enclave-info");
    }
  });

  // Below this line the response signature is verified on every call by RpcClient.
  const rpc = new RpcClient({ baseUrl: opts.baseUrl, attestationPubkeyHex });

  await step("session.begin returns server_nonce + expires_at", async () => {
    const r = await rpc.call("session.begin", {});
    if (!r?.server_nonce) throw new Error("missing server_nonce");
    if (!r.expires_at || r.expires_at <= Date.now()) throw new Error("bad expires_at");
    // server_nonce is base64 of 32 bytes.
    const nonceBytes = Buffer.from(r.server_nonce, "base64");
    if (nonceBytes.length !== 32) throw new Error(`server_nonce is ${nonceBytes.length} bytes, want 32`);
  });

  await step("auth.webauthn.assert.begin advertises PRF without leaking salt", async () => {
    const r = await rpc.call("auth.webauthn.assert.begin", {});
    if (!r?.options?.extensions?.prf) throw new Error("missing prf extension");
    // PRF salt MUST stay client-side; server must signal `prf: {}` only.
    if (r.options.extensions.prf.eval) {
      throw new Error("prf.eval should not be in the wire payload");
    }
  });

  await step("kv.get without bearer returns -32001 unauthorized", async () => {
    try {
      await rpc.call("kv.get", { key_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" });
      throw new Error("call should have failed");
    } catch (e) {
      if (e?.rpcError?.code !== -32001) throw new Error(`got ${e?.rpcError?.code} not -32001`);
    }
  });

  await step("unknown method returns -32601 method_not_found", async () => {
    try {
      await rpc.call("does.not.exist", {});
      throw new Error("call should have failed");
    } catch (e) {
      if (e?.rpcError?.code !== -32601) throw new Error(`got ${e?.rpcError?.code} not -32601`);
    }
  });

  if (opts.corsOrigin) {
    await step(`/api/info echoes ACAO when Origin is ${opts.corsOrigin}`, async () => {
      // Node fetch reliably sends the Origin header; the server's hono/cors
      // middleware echoes it back when the origin is in CORS_ALLOWED_ORIGINS.
      const r = await fetch(`${opts.baseUrl}/api/info`, { headers: { origin: opts.corsOrigin } });
      const acao = r.headers.get("access-control-allow-origin");
      if (!acao) throw new Error("server returned no Access-Control-Allow-Origin");
      if (acao !== opts.corsOrigin && acao !== "*") {
        throw new Error(`unexpected ACAO: ${acao}`);
      }
    });

    await step(`/api/info OPTIONS preflight from ${opts.corsOrigin} succeeds`, async () => {
      const r = await fetch(`${opts.baseUrl}/api/rpc`, {
        method: "OPTIONS",
        headers: {
          origin: opts.corsOrigin,
          "access-control-request-method": "POST",
          "access-control-request-headers": "content-type",
        },
      });
      if (r.status !== 204 && r.status !== 200) throw new Error(`preflight returned ${r.status}`);
      const acao = r.headers.get("access-control-allow-origin");
      if (!acao) throw new Error("preflight returned no Access-Control-Allow-Origin");
    });
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("smoke fatal:", err);
  process.exit(1);
});

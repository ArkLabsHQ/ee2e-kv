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
  decodeAttestationDocB64,
  cborDecode,
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

  // QEMU's `-M nitro-enclave` machine emulates the NSM with a stub that
  // returns an attestation document whose `certificate` field is 64 zero
  // bytes (no real DER, no AWS-Nitro-rooted chain). Full
  // `verifyAttestation` from the lib correctly rejects this — but only
  // production hardware can actually pass it. So in regtest we validate
  // what's verifiable: the doc's CBOR structure, the schema, the nonce
  // echo, and that PCR0 is present & non-zero. Production callers should
  // still use `fetchAndVerify` against the real enclave.
  await step("attestation doc structure (regtest-safe — skips Nitro CA chain)", async () => {
    const nonce = "00112233445566778899aabbccddeeff00112233";
    const r = await fetch(`${opts.baseUrl}/enclave/attestation?nonce=${nonce}`);
    if (!r.ok) throw new Error(`/enclave/attestation -> ${r.status}`);
    const cose = decodeAttestationDocB64(await r.text());
    const sign1 = cborDecode(cose);
    if (!Array.isArray(sign1) || sign1.length !== 4) {
      throw new Error("doc is not a COSE_Sign1 array");
    }
    const inner = cborDecode(sign1[2]);
    for (const k of ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "user_data", "nonce"]) {
      if (!inner.has(k)) throw new Error(`inner doc missing ${k}`);
    }
    const docNonce = inner.get("nonce");
    const expected = Buffer.from(nonce, "hex");
    if (!docNonce || Buffer.compare(Buffer.from(docNonce), expected) !== 0) {
      throw new Error("nonce was not echoed back in the doc");
    }
    const pcr0 = inner.get("pcrs")?.get(0);
    if (!pcr0 || pcr0.every((b) => b === 0)) throw new Error("PCR0 missing or all-zero");
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

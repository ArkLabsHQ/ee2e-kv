#!/usr/bin/env node
// Playwright driver for the QEMU regtest. Launches headless Chromium,
// attaches a CDP virtual authenticator with hasPrf=true, navigates to the
// fixture page (test/browser/dist/), calls window.runFlow(), and asserts:
//   - the WebAuthn → PRF → AES-GCM → KV roundtrip succeeds (recovered
//     plaintext matches what we put)
//   - cross-origin requests succeed (Access-Control-Allow-Origin echoes)
//   - the host-side opacity check: even with the supervisor's RUNTIME_TOKEN,
//     /v1/storage shows opaque ciphertext (no plaintext, no key name)
//
// Output: bash-grep-friendly PASS/FAIL lines. Exit 0 if all pass.
import { chromium } from "playwright";

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--base-url") out.baseUrl = argv[++i];
    else if (k === "--harness-url") out.harnessUrl = argv[++i];
    else if (k === "--expected-pcr0") out.expectedPcr0 = argv[++i];
    else if (k === "--runtime-token") out.runtimeToken = argv[++i];
  }
  if (!out.baseUrl || !out.harnessUrl) {
    console.error("Usage: browser.mjs --base-url <url> --harness-url <url> [--expected-pcr0 <hex>] [--runtime-token <hex>]");
    process.exit(2);
  }
  return out;
}

const PLAINTEXT = "regtest-secret-value";
const KEY_NAME = "regtest-key";

let passed = 0, failed = 0;
function pass(label) { console.log(`  PASS: ${label}`); passed++; }
function fail(label, err) { console.log(`  FAIL: ${label} — ${err?.message ?? err}`); failed++; }

async function step(label, fn) {
  try { await fn(); pass(label); } catch (err) { fail(label, err); }
}

async function main() {
  const opts = parseArgs(process.argv);
  console.log(`browser.mjs: baseUrl=${opts.baseUrl} harness=${opts.harnessUrl}`);

  // The harness fixture loads from http://localhost:5174 and then calls the
  // enclave's /v1/* + /enclave/* endpoints — those are served by the framework
  // supervisor, which doesn't speak CORS (only the user-app's /api/* does).
  // For the regtest fixture we side-step the same-origin policy with
  // --disable-web-security; this is fixture code, not a real consumer webapp,
  // so loosening browser security here is fine.
  const browser = await chromium.launch({
    headless: true,
    args: ["--disable-web-security", "--disable-site-isolation-trials"],
  });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  page.on("console", (msg) => console.log(`  [page ${msg.type()}] ${msg.text()}`));
  page.on("pageerror", (err) => console.log(`  [page error] ${err.message}`));

  // Attach CDP virtual authenticator with PRF.
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  console.log(`  attached virtual authenticator: ${authenticatorId}`);

  let flowResult = null;

  await step("harness page loads + window.runFlow defined", async () => {
    const res = await page.goto(opts.harnessUrl, { waitUntil: "domcontentloaded" });
    if (!res?.ok()) throw new Error(`harness fetch ${res?.status()}`);
    await page.waitForFunction(() => typeof window.runFlow === "function", null, { timeout: 5000 });
  });

  await step("runFlow() succeeds end-to-end", async () => {
    flowResult = await page.evaluate(
      async ({ baseUrl, expectedPcr0, plaintext, keyName }) => {
        return await window.runFlow({ baseUrl, expectedPcr0, plaintext, keyName });
      },
      { baseUrl: opts.baseUrl, expectedPcr0: opts.expectedPcr0, plaintext: PLAINTEXT, keyName: KEY_NAME },
    );
    if (!flowResult) throw new Error("runFlow returned nothing");
  });

  await step("recovered plaintext matches what we put (PRF → HKDF → AES-GCM round-trip)", async () => {
    if (!flowResult) throw new Error("no flow result");
    if (flowResult.recoveredPlaintext !== PLAINTEXT) {
      throw new Error(`got "${flowResult.recoveredPlaintext}" not "${PLAINTEXT}"`);
    }
  });

  if (opts.expectedPcr0) {
    await step("attestation pcr0 matches expected", async () => {
      if (!flowResult) throw new Error("no flow result");
      if (flowResult.pcr0 !== opts.expectedPcr0) {
        throw new Error(`got ${flowResult.pcr0}, expected ${opts.expectedPcr0}`);
      }
    });
  }

  await step("cross-origin Access-Control-Allow-Origin echoes harness origin", async () => {
    // Re-issue an /api/info from the page; check the response's CORS header.
    const cors = await page.evaluate(async (baseUrl) => {
      const r = await fetch(`${baseUrl}/api/info`);
      return r.headers.get("access-control-allow-origin");
    }, opts.baseUrl);
    if (!cors) throw new Error("missing Access-Control-Allow-Origin");
    if (cors !== opts.harnessUrl && cors !== "*") {
      throw new Error(`unexpected ACAO: ${cors}`);
    }
  });

  // Host-side opacity check — only runs if we have the supervisor's runtime token.
  if (opts.runtimeToken && flowResult) {
    await step("server-side opacity: /v1/storage bytes contain neither plaintext nor key name", async () => {
      const runtimeUrl = opts.baseUrl.replace(/:\d+$/, ":7073");
      const path = `kv/${flowResult.userId}/${flowResult.keyId}`;
      const r = await fetch(`${runtimeUrl}/v1/storage/${encodeURIComponent(path)}`, {
        headers: { authorization: `Bearer ${opts.runtimeToken}` },
      });
      if (!r.ok) throw new Error(`/v1/storage GET ${r.status}`);
      const raw = new Uint8Array(await r.arrayBuffer());
      // Storage stores JSON envelope { value, name_ct, version, updated_at }.
      const envelope = JSON.parse(new TextDecoder().decode(raw));
      const valueBytes = Buffer.from(envelope.value, "base64");
      const nameCtBytes = Buffer.from(envelope.name_ct, "base64");
      const haystack = Buffer.concat([valueBytes, nameCtBytes]).toString("binary");
      if (haystack.includes(PLAINTEXT)) throw new Error("plaintext found in storage bytes — E2EE invariant broken");
      if (haystack.includes(KEY_NAME)) throw new Error("key name found in storage bytes — name_ct not encrypted");
    });
  } else {
    console.log("  SKIP: server-side opacity check (no --runtime-token)");
  }

  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await browser.close();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("browser.mjs fatal:", err);
  process.exit(1);
});

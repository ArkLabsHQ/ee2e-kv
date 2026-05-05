import { fetchAndVerify } from "./enclave/info.js";
import { fetchApiInfo } from "./enclave/info.js";
import { RpcClient } from "./enclave/rpcClient.js";
import { register, assert } from "./auth/webauthnClient.js";
import {
  clearSession,
  decryptName,
  decryptValue,
  deriveKeyId,
  encryptName,
  encryptValue,
  getAuthToken,
  getSession,
  isAuthed,
  setFromAssertion,
} from "./auth/session.js";

const banner = document.getElementById("attestation-banner") as HTMLDivElement;
const authSection = document.getElementById("auth-section") as HTMLDivElement;
const kvSection = document.getElementById("kv-section") as HTMLDivElement;

async function bootstrap(): Promise<void> {
  let pubkeyHex: string;
  let pcr0Hex: string;
  try {
    const verified = await fetchAndVerify();
    pubkeyHex = verified.attestationPubkeyHex;
    pcr0Hex = verified.pcr0Hex;
  } catch (err) {
    banner.className = "banner err";
    banner.textContent = `Attestation FAILED: ${(err as Error).message}`;
    return;
  }

  const apiInfo = await fetchApiInfo();
  banner.className = "banner ok";
  banner.innerHTML = `
    <strong>Enclave verified.</strong>
    PCR0 (running): <code>${escapeHtml(pcr0Hex)}</code><br/>
    PCR0 (server-reported): <code>${escapeHtml(apiInfo.pcr0)}</code><br/>
    Attestation pubkey: <code>${escapeHtml(pubkeyHex)}</code><br/>
    Compare PCR0 above against the published reference for the release you trust.
  `;

  const rpc = new RpcClient({ attestationPubkeyHex: pubkeyHex, authToken: getAuthToken });
  renderAuth(rpc);
}

function renderAuth(rpc: RpcClient): void {
  if (isAuthed()) {
    renderKv(rpc);
    return;
  }
  authSection.innerHTML = `
    <h2>Get started</h2>
    <p>Register a passkey or sign in with an existing one.</p>
    <div class="row">
      <button id="btn-register">Register new passkey</button>
      <button id="btn-assert">Sign in with passkey</button>
    </div>
    <pre id="auth-log" hidden></pre>
  `;
  const log = document.getElementById("auth-log") as HTMLPreElement;
  const showErr = (e: unknown) => {
    log.hidden = false;
    log.textContent = `error: ${(e as Error).message ?? String(e)}`;
  };

  document.getElementById("btn-register")!.addEventListener("click", async () => {
    try {
      const r = await register(rpc);
      // Registration completes without PRF results — must assert to derive keys.
      log.hidden = false;
      log.textContent = `Registered user ${r.userId}. Now signing in to derive keys…`;
      const a = await assert(rpc, { userId: r.userId });
      if (!a.prfFirst) throw new Error("authenticator did not return PRF output — passkey is not E2EE-capable");
      await setFromAssertion({ userId: a.userId, authToken: a.authToken, expiresAt: a.expiresAt, prfFirst: a.prfFirst });
      renderKv(rpc);
    } catch (e) { showErr(e); }
  });

  document.getElementById("btn-assert")!.addEventListener("click", async () => {
    try {
      const a = await assert(rpc);
      if (!a.prfFirst) throw new Error("authenticator did not return PRF output");
      await setFromAssertion({ userId: a.userId, authToken: a.authToken, expiresAt: a.expiresAt, prfFirst: a.prfFirst });
      renderKv(rpc);
    } catch (e) { showErr(e); }
  });
}

interface KvListItem { key_id: string; name_ct: string; version: number }

function renderKv(rpc: RpcClient): void {
  authSection.innerHTML = `
    <p>Signed in as <code>${escapeHtml(getSession()!.userId)}</code>
       <button id="btn-logout">Log out</button></p>
  `;
  document.getElementById("btn-logout")!.addEventListener("click", () => {
    clearSession();
    location.reload();
  });

  kvSection.hidden = false;
  kvSection.innerHTML = `
    <h2>Your keys</h2>
    <ul id="kv-list" class="kv-list"></ul>
    <h3>Add or update</h3>
    <div class="row">
      <input id="kv-name" placeholder="key name" />
      <input id="kv-value" placeholder="value" />
      <button id="kv-put">Save</button>
    </div>
    <pre id="kv-log" hidden></pre>
  `;
  void refreshKv(rpc);

  document.getElementById("kv-put")!.addEventListener("click", async () => {
    const name = (document.getElementById("kv-name") as HTMLInputElement).value;
    const value = (document.getElementById("kv-value") as HTMLInputElement).value;
    const log = document.getElementById("kv-log") as HTMLPreElement;
    try {
      const keyId = await deriveKeyId(name);
      let expectedVersion = 0;
      try {
        const got = await rpc.call<{ version: number }>("kv.get", { key_id: keyId });
        expectedVersion = got.version;
      } catch {
        // not_found -> version 0
      }
      const valueB64 = await encryptValue(new TextEncoder().encode(value));
      const nameCt = await encryptName(name);
      await rpc.call("kv.put", {
        key_id: keyId,
        value: valueB64,
        name_ct: nameCt,
        expected_version: expectedVersion,
      });
      log.hidden = true;
      await refreshKv(rpc);
    } catch (e) {
      log.hidden = false;
      log.textContent = `error: ${(e as Error).message}`;
    }
  });
}

async function refreshKv(rpc: RpcClient): Promise<void> {
  const out = await rpc.call<{ items: KvListItem[] }>("kv.list", {});
  const list = document.getElementById("kv-list") as HTMLUListElement;
  list.innerHTML = "";
  for (const it of out.items) {
    const name = await decryptName(it.name_ct);
    const li = document.createElement("li");
    li.innerHTML = `
      <span><strong>${escapeHtml(name)}</strong> <code>v${it.version}</code></span>
      <span>
        <button data-id="${escapeHtml(it.key_id)}" class="btn-show">Show</button>
        <button data-id="${escapeHtml(it.key_id)}" data-v="${it.version}" class="btn-del">Delete</button>
      </span>
    `;
    list.appendChild(li);
  }
  list.querySelectorAll<HTMLButtonElement>(".btn-show").forEach((b) => {
    b.addEventListener("click", async () => {
      const keyId = b.dataset["id"]!;
      const got = await rpc.call<{ value: string }>("kv.get", { key_id: keyId });
      const pt = await decryptValue(got.value);
      alert(new TextDecoder().decode(pt));
    });
  });
  list.querySelectorAll<HTMLButtonElement>(".btn-del").forEach((b) => {
    b.addEventListener("click", async () => {
      const keyId = b.dataset["id"]!;
      const v = parseInt(b.dataset["v"]!, 10);
      await rpc.call("kv.del", { key_id: keyId, expected_version: v });
      await refreshKv(rpc);
    });
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c] as string));
}

void bootstrap();

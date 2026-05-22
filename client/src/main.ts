import { fetchAndVerify, KvClient } from "@e2ee-kv/sdk";

// API origin of the enclave. Empty ⇒ same-origin (dev uses the vite proxy);
// set VITE_ENCLAVE_URL at build time to target a deployed enclave.
const ENCLAVE_URL = import.meta.env.VITE_ENCLAVE_URL ?? "";

const banner = document.getElementById("attestation-banner") as HTMLDivElement;
const authSection = document.getElementById("auth-section") as HTMLDivElement;
const kvSection = document.getElementById("kv-section") as HTMLDivElement;

async function bootstrap(): Promise<void> {
  if (import.meta.env.DEV) {
    banner.className = "banner err";
    banner.innerHTML = `
      <strong>DEV MODE — attestation NOT verified.</strong>
      The reference SPA is talking to a stub runtime. Do not enter real secrets.
    `;
    renderAuth(new KvClient({ attestationPubkeyHex: null }));
    return;
  }

  // TEMPORARY: attestation bypassed. The supervisor's /v1 + /enclave routes
  // aren't CORS-reachable from the cross-origin SPA, so fetchAndVerify() can't
  // run. With this flag the client does NOT verify it's the genuine enclave —
  // remove VITE_SKIP_ATTESTATION (and add a same-origin proxy) before real use.
  if (import.meta.env.VITE_SKIP_ATTESTATION === "true") {
    banner.className = "banner err";
    banner.innerHTML = `
      <strong>Attestation SKIPPED — enclave NOT verified.</strong>
      Temporary bypass — do not enter real secrets.
    `;
    renderAuth(new KvClient({ attestationPubkeyHex: null, baseUrl: ENCLAVE_URL }));
    return;
  }

  let pubkeyHex: string;
  let pcr0Hex: string;
  try {
    const verified = await fetchAndVerify(ENCLAVE_URL);
    pubkeyHex = verified.attestationPubkeyHex;
    pcr0Hex = verified.pcr0Hex;
  } catch (err) {
    banner.className = "banner err";
    banner.textContent = `Attestation FAILED: ${(err as Error).message}`;
    return;
  }

  banner.className = "banner ok";
  banner.innerHTML = `
    <strong>Enclave verified.</strong>
    PCR0: <code>${escapeHtml(pcr0Hex)}</code><br/>
    Attestation pubkey: <code>${escapeHtml(pubkeyHex)}</code><br/>
    Compare PCR0 above against the published reference for the release you trust.
  `;

  renderAuth(new KvClient({ attestationPubkeyHex: pubkeyHex, baseUrl: ENCLAVE_URL }));
}

function renderAuth(kv: KvClient): void {
  if (kv.isAuthed()) {
    renderKv(kv);
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
    try { await kv.register(); renderKv(kv); } catch (e) { showErr(e); }
  });
  document.getElementById("btn-assert")!.addEventListener("click", async () => {
    try { await kv.assert(); renderKv(kv); } catch (e) { showErr(e); }
  });
}

function renderKv(kv: KvClient): void {
  authSection.innerHTML = `
    <p>Signed in as <code>${escapeHtml(kv.getSession()!.userId)}</code>
       <button id="btn-logout">Log out</button></p>
  `;
  document.getElementById("btn-logout")!.addEventListener("click", () => {
    kv.logout();
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
  void refreshKv(kv);

  document.getElementById("kv-put")!.addEventListener("click", async () => {
    const name = (document.getElementById("kv-name") as HTMLInputElement).value;
    const value = (document.getElementById("kv-value") as HTMLInputElement).value;
    const log = document.getElementById("kv-log") as HTMLPreElement;
    try {
      await kv.put(name, value);
      log.hidden = true;
      await refreshKv(kv);
    } catch (e) {
      log.hidden = false;
      log.textContent = `error: ${(e as Error).message}`;
    }
  });
}

async function refreshKv(kv: KvClient): Promise<void> {
  const items = await kv.list();
  const list = document.getElementById("kv-list") as HTMLUListElement;
  list.innerHTML = "";
  for (const it of items) {
    const li = document.createElement("li");
    li.innerHTML = `
      <span><strong>${escapeHtml(it.name)}</strong> <code>v${it.version}</code></span>
      <span>
        <button data-name="${escapeHtml(it.name)}" class="btn-show">Show</button>
        <button data-name="${escapeHtml(it.name)}" data-v="${it.version}" class="btn-del">Delete</button>
      </span>
    `;
    list.appendChild(li);
  }
  list.querySelectorAll<HTMLButtonElement>(".btn-show").forEach((b) => {
    b.addEventListener("click", async () => {
      const got = await kv.get(b.dataset["name"]!);
      alert(got?.value ?? "(not found)");
    });
  });
  list.querySelectorAll<HTMLButtonElement>(".btn-del").forEach((b) => {
    b.addEventListener("click", async () => {
      await kv.del(b.dataset["name"]!, parseInt(b.dataset["v"]!, 10));
      await refreshKv(kv);
    });
  });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c] as string));
}

void bootstrap();

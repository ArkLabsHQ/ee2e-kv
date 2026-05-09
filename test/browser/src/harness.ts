// Test fixture, NOT a product. Loaded by Playwright via a host-side static
// server. Exposes window.runFlow() that drives a full
// register → assert (PRF) → put → get → decrypt path against the live
// enclave at `baseUrl`, using the same SDK any consumer webapp would use.
import { fetchEnclaveInfo, KvClient } from "@e2ee-kv/sdk";

interface RunFlowOpts {
  baseUrl: string;
  expectedPcr0?: string;
  plaintext?: string;
  keyName?: string;
}

interface RunFlowResult {
  userId: string;
  pcr0: string;
  attestationPubkeyHex: string;
  recoveredPlaintext: string;
}

declare global {
  interface Window {
    runFlow: (opts: RunFlowOpts) => Promise<RunFlowResult>;
    flowError?: string;
  }
}

const log = document.getElementById("log") as HTMLPreElement;
function append(line: string) {
  log.textContent = (log.textContent ?? "") + "\n" + line;
}

async function runFlow(opts: RunFlowOpts): Promise<RunFlowResult> {
  const plaintext = opts.plaintext ?? "regtest-secret-value";
  const keyName = opts.keyName ?? "regtest-key";

  append(`runFlow: baseUrl=${opts.baseUrl}`);

  const info = await fetchEnclaveInfo(opts.baseUrl);
  if (!info.attestation_pubkey) throw new Error("enclave reports no attestation_pubkey");
  append(`pinned attestation_pubkey=${info.attestation_pubkey.slice(0, 16)}…`);

  const kv = new KvClient({
    baseUrl: opts.baseUrl,
    attestationPubkeyHex: info.attestation_pubkey,
  });

  const session = await kv.register();
  append(`registered user_id=${session.userId}`);

  const { version } = await kv.put(keyName, plaintext);
  append(`kv.put ${keyName} v${version}`);

  const got = await kv.get(keyName);
  if (!got) throw new Error(`kv.get returned null for ${keyName}`);
  append(`kv.get → "${got.value}"`);

  return {
    userId: session.userId,
    pcr0: "",
    attestationPubkeyHex: info.attestation_pubkey,
    recoveredPlaintext: got.value,
  };
}

window.runFlow = async (opts) => {
  try {
    return await runFlow(opts);
  } catch (err) {
    window.flowError = (err as Error).message ?? String(err);
    append(`ERROR: ${window.flowError}`);
    throw err;
  }
};

append("ready");

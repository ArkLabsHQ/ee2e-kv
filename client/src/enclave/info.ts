import type { ApiInfo } from "@e2ee-kv/protocol";
import { decodeAttestationDocB64, verifyAttestation, type VerifiedAttestation } from "./attestation.js";
import { bytesToHex } from "../crypto/encoding.js";

export interface EnclaveInfo {
  attestation_pubkey?: string;
  version?: string;
  previous_pcr0?: string;
  error?: string;
}

export async function fetchEnclaveInfo(baseUrl = ""): Promise<EnclaveInfo> {
  const res = await fetch(`${baseUrl}/v1/enclave-info`);
  if (!res.ok) throw new Error(`enclave-info: HTTP ${res.status}`);
  return (await res.json()) as EnclaveInfo;
}

export async function fetchApiInfo(baseUrl = ""): Promise<ApiInfo> {
  const res = await fetch(`${baseUrl}/api/info`);
  if (!res.ok) throw new Error(`api/info: HTTP ${res.status}`);
  return (await res.json()) as ApiInfo;
}

/** Fetch and verify the attestation document end-to-end. */
export async function fetchAndVerify(baseUrl = ""): Promise<VerifiedAttestation> {
  const info = await fetchEnclaveInfo(baseUrl);
  if (!info.attestation_pubkey) throw new Error("enclave reports no attestation_pubkey");
  const nonce = crypto.getRandomValues(new Uint8Array(20));
  const nonceHex = bytesToHex(nonce);
  const res = await fetch(`${baseUrl}/enclave/attestation?nonce=${nonceHex}`);
  if (!res.ok) throw new Error(`attestation: HTTP ${res.status}`);
  const text = await res.text();
  const cose = decodeAttestationDocB64(text);
  return verifyAttestation({ cose, expectedNonceHex: nonceHex, attestationPubkeyHex: info.attestation_pubkey });
}

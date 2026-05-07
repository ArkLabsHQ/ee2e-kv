/**
 * @enclave-sdk/browser — TypeScript SDK for verifying responses from a
 * Nitro-enclave-backed introspector-enclave runtime.
 *
 * Public surface:
 *   - {@link verifyAttestation}, {@link decodeAttestationDocB64} — verify a
 *     /enclave/attestation document end-to-end (cert chain to AWS Nitro root,
 *     COSE_Sign1 signature, nonce, PCR0, appKeyHash binding).
 *   - {@link fetchEnclaveInfo}, {@link fetchAndVerify} — convenience HTTP
 *     wrappers around /v1/enclave-info and /enclave/attestation.
 *   - {@link verifySchnorrSignature} — BIP-340 verify the runtime's
 *     X-Attestation-Signature header against SHA256(body).
 *   - {@link RpcClient} — thin JSON-RPC 2.0 client that pins an attestation
 *     pubkey and verifies every response signature.
 *   - Encoding helpers ({@link bytesToHex} etc.) so apps don't need a second
 *     copy of base64/hex/constant-time helpers.
 */
export {
  verifyAttestation,
  decodeAttestationDocB64,
  type AttestationDoc,
  type VerifiedAttestation,
} from "./attestation.js";
export { fetchEnclaveInfo, fetchAndVerify, type EnclaveInfo } from "./info.js";
export { verifySchnorrSignature } from "./schnorr.js";
export {
  RpcClient,
  RpcCallError,
  JsonRpcResponse,
  JsonRpcError,
  type RpcClientOpts,
} from "./rpcClient.js";
export {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  constTimeEq,
} from "./encoding.js";

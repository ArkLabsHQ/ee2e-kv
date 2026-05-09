/**
 * @e2ee-kv/sdk — TypeScript SDK for the enclave-e2ee-kv user-app.
 *
 * The SDK is the contract between any consumer webapp and the enclave:
 *   - {@link KvClient} — high-level put / get / del / list with WebAuthn-PRF
 *     auth and client-side AES-GCM. The recommended entry point for apps.
 *   - {@link verifyAttestation}, {@link fetchAndVerify} — verify the EIF's
 *     /enclave/attestation document against the AWS Nitro root.
 *   - {@link RpcClient} — JSON-RPC 2.0 client that pins an attestation
 *     pubkey and Schnorr-verifies every response.
 *   - Lower-level building blocks ({@link register}, {@link assert},
 *     {@link derivePrfKeys}, {@link aesGcmEncrypt}, etc.) for apps that
 *     need to step outside KvClient's defaults.
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
export { cborDecode } from "./cbor.js";
export {
  KvClient,
  type KvClientOpts,
  type KvSession,
  type KvItem,
  type KvGetResult,
} from "./kv.js";
export { register, assert, type RegisterResult, type AssertResult } from "./auth/webauthn.js";
export { derive as derivePrfKeys, PRF_SALT, type DerivedKeys } from "./auth/prfDerive.js";
export { aesGcmEncrypt, aesGcmDecrypt, importAesKey } from "./crypto/aesgcm.js";
export { hkdfSha256 } from "./crypto/hkdf.js";
export { hmacSha256, importHmacKey } from "./crypto/hmac.js";
export { base32Encode, base32Decode } from "./crypto/base32.js";

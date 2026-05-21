/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** API origin of the deployed enclave, e.g. https://enclave.vtxos.com.
   *  Unset in dev — the vite proxy serves /api, /v1, /enclave instead. */
  readonly VITE_ENCLAVE_URL?: string;
}

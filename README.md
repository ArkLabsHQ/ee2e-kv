# Enclave E2EE KV

Reference user-app for [ArkLabsHQ/introspector-enclave](https://github.com/ArkLabsHQ/introspector-enclave).
Demonstrates end-to-end-encrypted, versioned, per-user key/value storage on top
of a Nitro enclave. Plaintext values never reach the server. Storage paths
contain only HMAC-derived opaque key IDs.

## What's here

```
protocol/   shared TypeScript types + Zod schemas (JSON-RPC 2.0)
server/     Node.js 22+ user-app (hono + @simplewebauthn/server)
client/     Vite SPA — verifies attestation, runs the WebAuthn ceremonies,
            encrypts every value before sending it to the server
flake.nix   reproducible EIF build (vendored Node.js template — runs npm build)
enclave.yaml deployment config consumed by the framework CLI
```

## Threat model

- **Trusted at PCR0**: enclave code (framework supervisor + this app), authenticator at the moment of operation.
- **Untrusted**: AWS host, network, anyone with read access to S3 / SSM / KMS, *and the user-app handler itself for the purpose of value contents*.
- **Goals**:
  1. Confidentiality of value bytes against the user-app and below.
  2. Storage-path privacy: per-user key names do not appear in S3 paths.
  3. Integrity / authenticity of responses (BIP-340 Schnorr signatures from the framework supervisor).
  4. Replay resistance on writes (`expected_version`).

## What the framework gives us

- TLS termination inside the enclave at nitriding.
- BIP-340 Schnorr response signing — every response has `X-Attestation-Signature` and `X-Attestation-Pubkey` headers over `SHA256(body)`.
- Nitro attestation document — `GET /enclave/attestation?nonce=…`.
- KMS-backed AES-256-GCM at-rest storage — `PUT/GET/DELETE/LIST /v1/storage/...`, accessed via `Authorization: Bearer ${ENCLAVE_RUNTIME_TOKEN}`.

## What this app adds

| Layer | Mechanism |
|---|---|
| End-user auth | WebAuthn passkeys with PRF extension |
| Auth tokens | HS256 JWT, key from KMS-managed secret `auth_token_key`, jti LRU replay guard |
| Value encryption | AES-256-GCM with key derived client-side from PRF output via HKDF-SHA256 |
| Path privacy | `key_id = base32(HMAC-SHA256(path_key, name)).slice(0, 32)` |
| KV semantics | Per-user, versioned, optimistic-concurrency `kv.put` / `kv.del` |

## API surface

- `GET /api/info` — public, returns `{ pcr0, version, providers, rp }`. Schnorr-signed by the framework. Display the `pcr0` and compare against the published reference for the release you trust.
- `POST /api/rpc` — JSON-RPC 2.0. Methods listed in [`protocol/src/methods.ts`](protocol/src/methods.ts):
  - `session.begin`, `auth.webauthn.{register,assert}.{begin,finish}`, `auth.credentials.{list,delete}`
  - `kv.{get,put,del,list,batch_get,batch_put}`

Auth methods that require an existing session take `Authorization: Bearer <auth_token>`.

## How values stay opaque to the server

1. Registration runs the standard WebAuthn ceremony.
2. The first **assertion** asks the authenticator for `prfResults.first` using the fixed app salt `SHA256("enclave-kv-v1")`.
3. The client derives two keys via HKDF:
   - `value_key` (info: `"kv-v1-value-key"`) → AES-256-GCM
   - `path_key`  (info: `"kv-v1-path-key"`)  → HMAC-SHA256
4. Per value: random 12-byte nonce, AES-GCM, store `nonce ‖ ct ‖ tag` as the `value` field. The server stores it but cannot decrypt it.
5. The user-supplied key name is encrypted with `value_key` into `name_ct`. The server stores it. `kv.list` returns `name_ct`; the client decrypts.
6. The opaque on-the-wire `key_id` is `base32(HMAC-SHA256(path_key, name))` truncated to 20 bytes.

Synced passkeys (iCloud Keychain, Google Password Manager, 1Password) yield the same PRF output across devices — the user's data is portable. Two distinct passkeys give different PRF outputs (one passkey == one realm in phase 1).

**Lose your last passkey ⇒ data is unrecoverable.** This is not a bug.

## How clients verify the enclave

[`client/src/enclave/attestation.ts`](client/src/enclave/attestation.ts) ports the Go reference logic in `introspector-enclave/client/verify.go`:

1. Fetch `/enclave/attestation?nonce=<random hex>`.
2. Parse the COSE_Sign1 envelope.
3. Build the cert chain and anchor it to the AWS Nitro root cert (embedded in [`nitroRoot.ts`](client/src/enclave/nitroRoot.ts)).
4. Verify the COSE signature (ECDSA P-384 over SHA-384) via WebCrypto.
5. Verify the nonce matches what we sent.
6. Verify `SHA256(attestation_pubkey)` matches the `appKeyHash` embedded in `user_data` bytes 47..79.
7. Display PCR0 to the user — they compare it out-of-band against the published reference.

After that, every `/api/rpc` response is checked: [`rpcClient.ts`](client/src/enclave/rpcClient.ts) verifies the BIP-340 Schnorr signature over `SHA256(response_body)` using the pinned attestation pubkey, and rejects responses signed with any other key.

## Running it

### Prerequisites

- Node.js 22+
- For EIF build / deploy: a working installation of the framework CLI (`enclave`).

### Local dev (no enclave)

```bash
npm install
npm run build              # protocol -> client -> assets:copy -> server
npm -w e2ee-kv-server run dev   # in one terminal
npm -w e2ee-kv-client run dev   # in another (Vite dev server on :5173)
```

The dev server stubs the `ENCLAVE_RUNTIME_TOKEN` and `AUTH_TOKEN_KEY` env vars
(see [`server/src/config.ts`](server/src/config.ts)). Storage calls go to
`http://127.0.0.1:7073` — point that at a mock or run a local nitriding stack.

### Tests

```bash
npm test
```

Covers JWT sign/verify/expired/replay, session nonce single-use, KV
version-conflict semantics, AES-GCM round-trip, base32 round-trip, BIP-340
known-answer verification, and JSON-RPC schema completeness.

### EIF build

```bash
# 1. Push this repo to GitHub.
# 2. Update enclave.yaml: nix_owner / nix_repo / nix_rev / nix_hash.
# 3. Compute npm vendor hash (CLI helper):
enclave setup
# 4. Build the EIF:
enclave build
# 5. Deploy:
enclave run
```

## Open follow-ups

- Lift `client/src/enclave/` into a published `@arklabs/enclave-client-ts` package once the API stabilizes.
- Cross-key transactional `kv.batch_put`. Today batch is per-item atomic.
- Multi-passkey shared data realms via a wrapped master key. Today: one passkey == one realm.
- Upstream the framework's Node.js flake template so apps don't need to vendor `flake.nix` to run `npm run build`.

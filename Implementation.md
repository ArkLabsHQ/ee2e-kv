# Implementation Report — enclave-e2ee-kv

End-to-end-encrypted KV System using the enclave framework.

## Architecture

Trust root is the framework's PCR0 + Schnorr-signed responses. Layered on top:

- WebAuthn passkey auth with PRF
- Client-side AES-256-GCM keyed off PRF output (server never sees plaintext)
- HMAC-hashed storage keys (user key names never leak into S3 paths)

The SDK (`@e2ee-kv/sdk`) is the contract between any consumer webapp and the enclave. It owns the full E2EE path; the reference SPA and the regtest harness are demo / test consumers of the SDK, not parallel implementations.

## Workspaces

| Workspace | Role |
|---|---|
| `@e2ee-kv/protocol` | Shared Zod schemas + JSON-RPC error codes |
| `@e2ee-kv/sdk` | E2EE SDK: attestation verification, BIP-340 Schnorr response signing, WebAuthn-PRF auth, AES-GCM/HMAC primitives, high-level `KvClient` |
| `e2ee-kv-server` | Hono JSON-RPC + KV server; runs in the EIF; persists via enclave runtime's `/v1/storage` |
| `e2ee-kv-client` | Reference SPA — UI consumer of the SDK |
| `@enclave-test/browser` | Playwright fixture for the regtest; consumes the SDK |

## SDK (`@e2ee-kv/sdk`)

| Surface | Purpose |
|---|---|
| `KvClient` | High-level entry point. `register()` / `assert()` derive E2EE keys from PRF output and hold them in memory; `put` / `get` / `del` / `list` take and return plaintext, encrypting transparently. |
| `verifyAttestation`, `fetchAndVerify`, `fetchEnclaveInfo` | Attestation chain (COSE_Sign1 → ECDSA P-384 → X.509 → AWS Nitro root → PCR0 + appKeyHash binding). |
| `RpcClient` | JSON-RPC 2.0 client that pins an attestation pubkey and Schnorr-verifies every response. |
| `register`, `assert`, `derivePrfKeys` | Lower-level WebAuthn ceremonies + HKDF derivation, for apps that need to step outside `KvClient` defaults.

Consumers depend on `@e2ee-kv/sdk` only — no need to reimplement WebAuthn-PRF, HKDF, AES-GCM, or the wire format.

## Server

Hono + CORS middleware allow-listed via `CORS_ALLOWED_ORIGINS`. JSON-RPC 2.0 dispatcher with per-method auth requirements. WebAuthn ceremonies via `@simplewebauthn/server` v13 (PRF, UV, discoverable required), `server_nonce` bound into the challenge. HS256 JWT with `jti` LRU. Versioned per-user KV with `version_conflict` semantics; storage paths constructed from client-supplied opaque `key_id`.



## Tests

**Unit (Vitest):**

| Workspace | Coverage |
|---|---|
| `@e2ee-kv/sdk` | CBOR (incl. indefinite-length encoding), BIP-340 Schnorr KAT vectors, AES-GCM round-trip, base32 RFC 4648 vectors |
| `e2ee-kv-server` | JWT sign/verify/replay, session nonce single-use + TTL, KV handlers (version conflict, batch atomicity, last-credential refusal) |
| `@e2ee-kv/protocol` | Schema round-trip on every method |

**Regtest** (`test/run.sh`) — 10 phases: pre-flight → build EIF → build harness → locate supervisor → mock AWS up → tofu apply → launch supervisor → wait-for-ready → smoke → browser flow → cleanup. Mock AWS stack (LocalStack + local-kms-proxy + mock-imds) vendored from upstream.

- **Smoke** (`test/smoke.mjs`, Node) — `/healthz`, `/api/info` shape, `/v1/enclave-info` exposes `attestation_pubkey`, COSE_Sign1 structural check, `session.begin` nonce shape, PRF-salt not on the wire, JSON-RPC error codes (`-32001`, `-32601`), CORS ACAO echo + OPTIONS preflight.
- **Browser** (`test/browser.mjs` + `test/browser/`, Playwright headless Chromium with CDP virtual authenticator + `hasPrf: true`) — fixture page loads → `KvClient.register()` → `KvClient.put(name, value)` → `KvClient.get(name)` → recovered plaintext matches.

## CI

| Workflow | Trigger | Job |
|---|---|---|
| `tests.yml` | every push/PR | typecheck + unit + build |
| `regtest.yml` | every push/PR | full QEMU regtest |

## Attestation coverage

| Check | Status |
|---|---|
| COSE_Sign1 structure (fields, nonce echo, PCR0 non-zero) | Covered by smoke |
| Schnorr response signature on every RPC call | Covered by smoke + browser (every `KvClient` call) |
| BIP-340 algorithm (KAT vectors) | Covered by unit tests |
| CBOR decoder (incl. indefinite-length) | Covered by unit tests |
| Full chain: AWS Nitro root → CA → attestation pubkey | Not automated |
| PCR0 binding to known-good measurement | Not automated |

QEMU's NSM stub returns 64 zero bytes for the `certificate` field, so the regtest can't exercise the happy-path chain. `verifyAttestation` is shipped and unit-tested at the primitive level; full-chain verification requires real Nitro hardware.



# Regtest harness

Boots the EIF in QEMU, drives it through a Node smoke client and a Playwright headless-browser flow, then tears everything down. Two products are exercised:

1. **The server** — JSON-RPC API + WebAuthn + KV. Tested via the smoke client.
2. **`@enclave-sdk/browser`** — the library a real consumer webapp would consume. Tested via both the smoke client (Node) and the harness fixture page (real browser).

The reference SPA in `client/` is uninvolved here — the regtest uses its own minimal fixture page (`test/browser/`) so the SPA stays out of the trust path.

## Quick start

```sh
# One-shot, ~250MB Chromium download:
make regtest-deps

# Boot EIF in QEMU, run smoke + browser flows, tear down:
make regtest

# Same, but reuse an existing EIF:
make regtest-fast
```

## Prerequisites

| Tool | How to get it |
|---|---|
| `nix` | https://nixos.org/download (also handles QEMU + vhost-device-vsock) |
| `docker` | for the mock AWS stack (KMS / KMS-proxy / LocalStack / mock-imds) |
| `enclave` CLI | `go install github.com/ArkLabsHQ/introspector-enclave/cli/cmd/enclave@latest` (also produces the host-side supervisor binary at `.enclave/artifacts/supervisor` as part of `enclave build`) |
| `tofu` | OpenTofu — `https://opentofu.org/docs/intro/install/` |
| `python3` | for the harness static server |
| `vsock` + `vsock_loopback` modules | `sudo modprobe vsock vsock_loopback` |

The QEMU/`vhost-device-vsock` stack is auto-entered via `nix develop test/qemu/` if those tools are missing on your `PATH`.

## What it asserts

### Smoke (`test/smoke.mjs` — Node, no browser)
1. `GET /healthz` → 200 ok
2. `GET /api/info` returns `version` + `providers: ["webauthn"]` + `rp.id`
3. `GET /v1/enclave-info` exposes `attestation_pubkey`
4. **Attestation chain verifies** via `@enclave-sdk/browser`'s `fetchAndVerify` (cert chain → AWS Nitro root → COSE_Sign1 sig → nonce → PCR0 → appKeyHash binding)
5. `session.begin` returns a 32-byte base64 `server_nonce` + `expires_at`
6. `auth.webauthn.assert.begin` advertises `prf: {}` only (no `eval` on the wire — proves the client-side-only PRF salt convention)
7. `kv.get` without bearer → JSON-RPC `-32001 unauthorized`
8. Every signed response passes BIP-340 Schnorr verify (done implicitly by `RpcClient`)
9. Unknown method → `-32601 method_not_found`

### Browser (`test/browser.mjs` + `test/browser/` fixture — Playwright headless Chromium)
1. Fixture page loads + `window.runFlow` defined
2. `runFlow` succeeds end-to-end (register passkey → assert with PRF → derive `value_key`/`path_key` → `kv.put` → `kv.get` → AES-GCM decrypt)
3. Recovered plaintext matches what we encrypted (PRF → HKDF → AES-GCM round-trip)
4. Attestation `pcr0` matches `pcr.json` from `enclave build`
5. Cross-origin `Access-Control-Allow-Origin` echoes the harness origin (proves CORS works for a real consumer)
6. **Server-side opacity check** — with the supervisor's `RUNTIME_TOKEN`, the host fetches the raw S3 bytes via `/v1/storage`. Asserts the `value` and `name_ct` blobs contain neither the plaintext nor the user-supplied key name. *This is the only step that proves the E2EE invariant holds.*

## Layout

```
test/
├── run.sh                   # main 10-phase orchestrator
├── smoke.mjs                # Node smoke client (uses @enclave-sdk/browser)
├── browser.mjs              # Playwright driver + host-side opacity check
├── browser/                 # `@enclave-test/browser` workspace — fixture page
│   ├── index.html
│   └── src/harness.ts       # imports @enclave-sdk/browser, exposes window.runFlow
├── mock-runtime.mjs         # stand-in supervisor for `make dev` (NOT used by regtest)
└── qemu/                    # vendored from upstream — see UPSTREAM.md
    ├── boot.sh              # QEMU launcher (lifted from upstream `boot_qemu`)
    ├── flake.nix            # nixos-25.05 dev shell — QEMU 9.2.4 + vhost-device-vsock 0.3.0
    ├── docker-compose.yml   # KMS + KMS-proxy + LocalStack + mock-imds
    ├── heartbeat.py         # AF_VSOCK :9000 echo (0xB7)
    ├── seed.yaml            # pre-seeded local-kms test key
    ├── local-kms-proxy/     # Go service: wraps KMS Decrypt for attestation flow
    └── mock-imds/           # Go service: fake EC2 IMDSv2
```

## Phases (roughly)

```
[1/10] Pre-flight              — tools, /dev/vsock, free ports, docker compose down
[2/10] Build EIF               — `enclave build` (cached after first run)
[3/10] Build harness fixture   — `npm -w @enclave-test/browser run build`
[4/10] Locate host supervisor  — use the binary `enclave build` already wrote
[5/10] Mock services up        — docker compose
[6/10] Tofu apply              — scaffold + apply with env_values overlay
[7/10] Launch supervisor       — relauncher pattern; supervisor watchdog boots QEMU via ENCLAVE_START_CMD
[8/10] Wait for ready          — poll `https://localhost:8443/healthz`
[9/10] Smoke                   — `node test/smoke.mjs`
[10/10] Browser                — start harness static server, then `node test/browser.mjs`
```

Cleanup happens via `trap … EXIT` regardless of which phase failed.

## Troubleshooting

- `Error: /dev/vsock not present` → `sudo modprobe vsock vsock_loopback`
- `Bind for 0.0.0.0:1338 failed: port is already allocated` → another docker compose stack is using the port. Phase 1 already runs `docker compose down -v` against `test/qemu/`; if a different stack is hogging the port, find it with `docker ps | grep 1338`.
- `legacy flake.nix at repo root` → run from the repo root, NOT from `enclave/`. The CLI's `findRepoRoot` walks up from cwd looking for `enclave/enclave.yaml`.
- Smoke step 4 (attestation) fails with `chain does not anchor to AWS Nitro root` → the EIF was built against a fork that doesn't ship the AWS Nitro test certs. The upstream `qemu-system-x86_64 -M nitro-enclave` machine type produces AWS-rooted attestations by default.
- Browser step 1 hangs → check that `npx playwright install chromium` ran successfully. `~/.cache/ms-playwright/chromium-*` should exist.
- Browser step 6 SKIP → no `--runtime-token` was passed. The supervisor doesn't expose a `/runtime-token` endpoint by default; this is a known gap and step 6 is non-blocking.

## Resync from upstream

When upstream changes a vendored file (in `test/qemu/`), clone introspector-enclave somewhere temporary and diff:

```sh
git clone --depth 1 https://github.com/ArkLabsHQ/introspector-enclave /tmp/introspector-enclave
diff -u /tmp/introspector-enclave/test/heartbeat.py test/qemu/heartbeat.py
# review, update if appropriate, bump UPSTREAM.md commit SHA
```

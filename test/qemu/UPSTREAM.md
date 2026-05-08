# Upstream provenance

Files in this directory are vendored from `ArkLabsHQ/introspector-enclave/test/`.
Resync by diffing against the upstream paths listed below.

## Source

- Repo: `github.com/ArkLabsHQ/introspector-enclave`
- Pinned commit: `04b08166107c7e6da329638aa7e244ee5f772f86`
- Upstream local checkout: `/home/joshua/introspector-enclave/test/`

## File mapping

| Local | Upstream | Notes |
|---|---|---|
| `flake.nix` | `test/flake.nix` | Verbatim — pins QEMU 9.2.4 + vhost-device-vsock 0.3.0 via nixos-25.05 |
| `flake.lock` | `test/flake.lock` | Verbatim |
| `heartbeat.py` | `test/heartbeat.py` | Verbatim — AF_VSOCK :9000 echo, byte 0xB7 |
| `seed.yaml` | `test/seed.yaml` | Verbatim — pre-seeded local-kms test key |
| `docker-compose.yml` | `test/docker-compose.yml` | **Modified** — Dockerfile build contexts narrowed to each service's own dir; upstream `test-runner` profile dropped (we run from host) |
| `local-kms-proxy/` | `test/local-kms-proxy/` | Source files verbatim; **Dockerfile rewritten** to use `./` context instead of upstream's repo-root context |
| `mock-imds/` | `test/mock-imds/` | Source files verbatim; **Dockerfile rewritten** as above |

## What we did NOT vendor

- `test/run.sh` (54KB) — we write our own at `../run.sh` tailored to e2ee-kv's smaller phase set (no migration test).
- `test/integration-test.sh` (17KB bash assertions) — replaced by `test/smoke.mjs` (Node, imports `@enclave-sdk/browser`).
- `test/Dockerfile.runner`, `test/Dockerfile.supervisor` — we run the harness from the host, not in a container.
- `test/app/` — upstream's reference user-app; we have our own at `enclave-e2ee-kv/server/`.
- `test/.github/`, `test/tofu-*.log`, `test/README.md` — not relevant here.

## Resync workflow

When upstream changes a file we mirror:

```sh
diff -u /home/joshua/introspector-enclave/test/heartbeat.py test/qemu/heartbeat.py
# review, then update if appropriate
```

For files we modified (the Dockerfiles + docker-compose.yml), expect a structural
diff but identical functional behaviour.

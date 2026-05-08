#!/usr/bin/env bash
# enclave-e2ee-kv local QEMU regtest harness.
#
# Builds the EIF, brings up the mock AWS stack + host-side supervisor,
# boots the EIF in QEMU, runs the Node smoke client, then drives a real
# WebAuthn → PRF → AES-GCM → KV roundtrip via Playwright headless
# Chromium against a fixture page (test/browser/).
#
# Usage:
#   ./test/run.sh             Build a fresh EIF, run the full flow
#   EIF=path/to/image.eif ./test/run.sh
#                             Reuse a pre-built EIF (skip phase 2)
#
# Prerequisites:
#   - nix develop ./test/qemu (provides QEMU 9.2.4 + vhost-device-vsock 0.3.0)
#   - docker compose (mock AWS services)
#   - enclave CLI on PATH (also produces the host-side supervisor binary
#     as part of `enclave build`, at .enclave/artifacts/supervisor)
#   - npx playwright install chromium (run `make regtest-deps` once)
#   - python3 (for the harness static server)
#   - vsock + vsock_loopback kernel modules loaded
set -euo pipefail

# --- Paths ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$(realpath "$0")"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Tunables ---
HARNESS_PORT="${HARNESS_PORT:-5174}"
HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
RUNTIME_PORT="${RUNTIME_PORT:-7073}"
EXPECTED_PCR0="${EXPECTED_PCR0:-}"   # filled in by phase 2 if not set
EIF_PATH="${EIF:-}"                  # if set, skip the EIF build phase

# --- PIDs / state for cleanup ---
HARNESS_PID=""
SUP_PID=""
SUPERVISOR_PIDFILE=/tmp/supervisor.pid
RUNTIME_TOKEN=""

# Bash-grep-friendly result reporting.
PASSED=0
FAILED=0
pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1${2:+ — $2}"; FAILED=$((FAILED + 1)); }

# --- Cleanup trap ---
cleanup() {
  echo ""
  echo "=== Cleaning up ==="
  [ -n "$HARNESS_PID" ] && kill "$HARNESS_PID" 2>/dev/null && echo "  Stopped harness server" || true
  if [ -n "$SUP_PID" ]; then
    kill -TERM "$SUP_PID" 2>/dev/null && echo "  Sent TERM to supervisor relauncher" || true
  fi
  [ -f "$SUPERVISOR_PIDFILE" ] && kill "$(cat "$SUPERVISOR_PIDFILE")" 2>/dev/null || true
  [ -f /tmp/enclave-boot.pid ] && kill "$(cat /tmp/enclave-boot.pid)" 2>/dev/null || true
  pkill -f vhost-device-vsock 2>/dev/null || true
  pkill -f "$SCRIPT_DIR/qemu/heartbeat.py" 2>/dev/null || true
  ( cd "$SCRIPT_DIR/qemu" && docker compose down -v --timeout 10 2>/dev/null ) || true
  rm -f /tmp/supervisor.pid /tmp/supervisor-relauncher.sh /tmp/enclave-boot.pid
  rm -f "/tmp/vhost4.socket"
  echo ""
  echo "=== Result: $PASSED passed, $FAILED failed ==="
  exit $FAILED
}
trap cleanup EXIT INT TERM

# --- Helpers ---
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' required on PATH" >&2; exit 1; }
}

free_port() {
  local p="$1"
  local pid
  pid=$(ss -ltnp 2>/dev/null | awk -v p=":$p" '$4 ~ p {print $0}' | grep -oP 'pid=\K\d+' | head -1 || true)
  if [ -n "$pid" ]; then
    echo "  Freeing port $p (pid $pid)"
    kill "$pid" 2>/dev/null || true
    sleep 0.5
  fi
}

# === Phase 1: pre-flight ===
echo ""
echo "=== [1/10] Pre-flight ==="
need_cmd nix
need_cmd docker
need_cmd enclave
need_cmd npx
need_cmd python3
need_cmd jq

# Auto-enter the test/qemu nix dev shell if QEMU+vhost-device-vsock missing.
if ! command -v vhost-device-vsock >/dev/null 2>&1 || ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "  QEMU/vhost-device-vsock missing — re-execing under nix develop"
  exec nix develop "$SCRIPT_DIR/qemu" --command "$SCRIPT_PATH" "$@"
fi

# Verify Playwright Chromium is installed.
if ! npx --no-install playwright --version >/dev/null 2>&1; then
  echo "Error: playwright not installed. Run: make regtest-deps" >&2
  exit 1
fi

if [ ! -e /dev/vsock ]; then
  echo "Error: /dev/vsock not present. Load: sudo modprobe vsock vsock_loopback" >&2
  exit 1
fi

free_port "$HOST_TLS_PORT"
free_port "$RUNTIME_PORT"
free_port "$HARNESS_PORT"
free_port 9090

# Tear down any docker stack from a previous run before we try to bind the
# mock-service ports below (ports 8080/4000/4566/1338).
( cd "$SCRIPT_DIR/qemu" && docker compose down -v --timeout 5 2>/dev/null ) || true

# Warn if pinned nix_rev != HEAD of the GitHub remote.
HEAD_REV=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "")
PINNED_REV=$(awk -F'"' '/nix_rev:/ {print $2; exit}' "$REPO_ROOT/enclave/enclave.yaml" || echo "")
if [ -n "$HEAD_REV" ] && [ -n "$PINNED_REV" ] && [ "$HEAD_REV" != "$PINNED_REV" ]; then
  echo "  Warning: nix_rev ($PINNED_REV) != HEAD ($HEAD_REV)."
  echo "           Run 'cd enclave && enclave setup' after pushing if you want regtest"
  echo "           to validate the latest commit."
fi

# === Phase 2: build EIF ===
if [ -z "$EIF_PATH" ]; then
  echo ""
  echo "=== [2/10] Building EIF ==="
  # Run from REPO_ROOT — the CLI's findRepoRoot walks up looking for
  # enclave/enclave.yaml, so cwd must be the parent (not enclave/ itself).
  ( cd "$REPO_ROOT" && enclave build )
  EIF_PATH="$REPO_ROOT/.enclave/artifacts/image.eif"
fi
EIF_PATH="$(realpath "$EIF_PATH")"
[ -f "$EIF_PATH" ] || { echo "Error: EIF not found at $EIF_PATH" >&2; exit 1; }
echo "  EIF: $EIF_PATH"

if [ -z "$EXPECTED_PCR0" ] && [ -f "$REPO_ROOT/.enclave/artifacts/pcr.json" ]; then
  EXPECTED_PCR0=$(jq -r '.pcr0 // empty' "$REPO_ROOT/.enclave/artifacts/pcr.json" 2>/dev/null || echo "")
fi
echo "  Expected PCR0: ${EXPECTED_PCR0:-<unknown>}"

# === Phase 3: build harness fixture ===
echo ""
echo "=== [3/10] Building harness fixture ==="
( cd "$REPO_ROOT" && npm -w @enclave-test/browser run build >/dev/null 2>&1 )
echo "  test/browser/dist/ ready"

# === Phase 4: locate host-side supervisor ===
# `enclave build` produced both image.eif and the supervisor binary in
# .enclave/artifacts/. No separate go build needed.
echo ""
echo "=== [4/10] Locating host-side supervisor ==="
ENCLAVE_SUPERVISOR="$REPO_ROOT/.enclave/artifacts/supervisor"
[ -x "$ENCLAVE_SUPERVISOR" ] || { echo "Error: supervisor not found at $ENCLAVE_SUPERVISOR (did 'enclave build' run?)" >&2; exit 1; }
echo "  Supervisor: $ENCLAVE_SUPERVISOR"

# === Phase 5: bring up mock AWS services ===
echo ""
echo "=== [5/10] Starting mock AWS services ==="
( cd "$SCRIPT_DIR/qemu" && docker compose up -d --wait )
echo "  KMS / KMS-proxy / LocalStack / mock-imds healthy"

# === Phase 6: tofu apply ===
echo ""
echo "=== [6/10] Scaffolding + applying tofu (LocalStack SSM/S3 + KMS encryption of secrets) ==="
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="us-east-1"
export AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000"
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_LOGS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_IAM="http://127.0.0.1:4566"
# Catch-all for anything else (CloudFormation, etc.) — LocalStack hosts most
# AWS services on the same edge port.
export AWS_ENDPOINT_URL="http://127.0.0.1:4566"

# Scaffold the tofu module if it doesn't already exist (idempotent — `enclave
# tofu` skips files that exist).
( cd "$REPO_ROOT" && enclave tofu )

# Set the `local` flag (skips VPC/EC2/AMI data sources, which only resolve
# against real AWS — LocalStack's free tier doesn't ship a working EC2 endpoint).
# The env_values overlay for RP_ORIGIN / CORS_ALLOWED_ORIGINS is intentionally
# omitted here: the framework's SSM env_override path is currently broken
# (supervisor reads SSM but doesn't propagate into the user-app's exec env),
# so we rely on the EIF's baked-in defaults — see enclave/enclave.yaml.
TOFU_DIR="$REPO_ROOT/tofu"
cat > "$TOFU_DIR/env_values.auto.tfvars.json" <<EOF
{
  "local": true
}
EOF

# Wipe stale tofu state before applying — `docker compose down -v` destroys
# LocalStack's volumes between runs, so any state file from a previous run
# points at resources that no longer exist. Force a clean apply.
rm -rf "$TOFU_DIR/.terraform" "$TOFU_DIR"/terraform.tfstate*

# Seed the KMSKeyID SSM parameter BEFORE tofu apply — the tofu module reads
# it via `data "aws_ssm_parameter" "kms_key_id_lookup"` to wire enclave secret
# encryption to the local-kms-proxy seeded key.
aws ssm put-parameter --endpoint-url http://127.0.0.1:4566 --region us-east-1 \
  --name "/dev/e2ee-kv/KMSKeyID" --value "test-key-id" --type String --overwrite --no-cli-pager \
  >/dev/null

tofu -chdir="$TOFU_DIR" init -input=false -no-color > /tmp/tofu-init.log 2>&1 \
  || { tail -30 /tmp/tofu-init.log >&2; exit 1; }
tofu -chdir="$TOFU_DIR" apply -auto-approve -input=false -compact-warnings -no-color > /tmp/tofu-apply.log 2>&1 \
  || { tail -30 /tmp/tofu-apply.log >&2; exit 1; }
echo "  Tofu state applied; SSM KMS key seeded"

# === Phase 7: launch supervisor (boots QEMU via watchdog) ===
echo ""
echo "=== [7/10] Launching host-side supervisor ==="
EIF_ABS_PATH="$EIF_PATH"
SUP_RELAUNCHER=/tmp/supervisor-relauncher.sh
cat > "$SUP_RELAUNCHER" <<'SUPER'
#!/usr/bin/env bash
set -u
SUP_BIN="$1"; PIDFILE="$2"
child=""
trap '[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; [ -n "$child" ] && wait "$child" 2>/dev/null; rm -f "$PIDFILE"; exit 0' TERM INT
while :; do
  "$SUP_BIN" &
  child=$!
  echo "$child" > "$PIDFILE"
  wait "$child" 2>/dev/null || true
  sleep 1
done
SUPER
chmod +x "$SUP_RELAUNCHER"

export ENCLAVE_AWS_REGION=us-east-1
export ENCLAVE_DEPLOYMENT=dev
export ENCLAVE_APP_NAME=e2ee-kv
export ENCLAVE_SUPERVISOR_ADDR="127.0.0.1:8444"
export GVPROXY_FORWARD_PORTS="$HOST_TLS_PORT:443 $RUNTIME_PORT 9090"
export IMDS_PROXY_TARGET="127.0.0.1:1338"
export ENCLAVE_URL="https://127.0.0.1:$HOST_TLS_PORT"
export ENCLAVE_EIF_PATH="$EIF_ABS_PATH"
export ENCLAVE_SUPERVISOR_BINARY_PATH="$ENCLAVE_SUPERVISOR"
export ENCLAVE_SUPERVISOR_RESTART_CMD="kill \$(cat $SUPERVISOR_PIDFILE)"
export ENCLAVE_STOP_CMD="kill \$(cat /tmp/enclave-boot.pid) 2>/dev/null; sleep 3"
export ENCLAVE_START_CMD="nohup \"$SCRIPT_DIR/qemu/boot.sh\" \"$EIF_ABS_PATH\" >> /tmp/boot-qemu.log 2>&1 &"

: > /tmp/boot-qemu.log
"$SUP_RELAUNCHER" "$ENCLAVE_SUPERVISOR" "$SUPERVISOR_PIDFILE" &
SUP_PID=$!
sleep 2
[ -s "$SUPERVISOR_PIDFILE" ] || { echo "Error: supervisor pidfile not populated" >&2; exit 1; }
echo "  Supervisor relauncher pid $SUP_PID, child pid $(cat "$SUPERVISOR_PIDFILE") on http://127.0.0.1:8444"

# Capture the supervisor's runtime token for the host-side opacity check.
RUNTIME_TOKEN=$(curl -sk --max-time 5 http://127.0.0.1:8444/runtime-token 2>/dev/null | jq -r '.token // empty' || echo "")
if [ -z "$RUNTIME_TOKEN" ]; then
  echo "  Note: supervisor /runtime-token endpoint did not return a token —"
  echo "        the host-side opacity check will be skipped (browser test still runs)."
fi

# === Phase 8: wait for enclave ready ===
echo ""
echo "=== [8/10] Waiting for enclave to become ready ==="
seconds=0
while [ "$seconds" -lt 120 ]; do
  http_code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
    "https://localhost:$HOST_TLS_PORT/healthz" 2>/dev/null || echo "000")
  if [ "$http_code" = "200" ]; then
    echo "  Enclave responding at https://localhost:$HOST_TLS_PORT/healthz (${seconds}s)"
    break
  fi
  sleep 2
  seconds=$((seconds + 2))
done
[ "$http_code" = "200" ] || { echo "Error: enclave did not become ready within 120s" >&2; tail -50 /tmp/boot-qemu.log >&2 || true; exit 1; }

# Capture the live attestation doc as a fixture for offline parser debugging.
echo ""
echo "  Capturing live attestation doc → test/qemu/live-attestation.b64"
curl -sk --max-time 5 "https://localhost:$HOST_TLS_PORT/enclave/attestation?nonce=00112233445566778899aabbccddeeff00112233" > "$SCRIPT_DIR/qemu/live-attestation.b64" 2>/dev/null || true

# === Phase 9: smoke ===
echo ""
echo "=== [9/10] Smoke (HTTP/JSON-RPC, no browser) ==="
# `|| true` keeps `set -e` from aborting the harness when smoke fails — we
# still want phase 10 (browser) to run so the user sees the full picture.
NODE_TLS_REJECT_UNAUTHORIZED=0 node "$SCRIPT_DIR/smoke.mjs" \
  --base-url "https://localhost:$HOST_TLS_PORT" \
  --cors-origin "http://localhost:$HARNESS_PORT" \
  ${EXPECTED_PCR0:+--expected-pcr0 "$EXPECTED_PCR0"} \
  | tee /tmp/smoke.log || true
SMOKE_RC=${PIPESTATUS[0]}
if [ "$SMOKE_RC" -eq 0 ]; then pass "smoke.mjs"; else fail "smoke.mjs" "exit $SMOKE_RC"; fi

# === Phase 10: harness static server + browser flow ===
echo ""
echo "=== [10/10] Browser flow (Playwright + CDP virtual authenticator) ==="
echo "  Starting harness static server on :$HARNESS_PORT"
python3 -m http.server "$HARNESS_PORT" --directory "$SCRIPT_DIR/browser/dist" >/tmp/harness.log 2>&1 &
HARNESS_PID=$!
# Wait for the static server.
for _ in $(seq 1 20); do
  curl -sf -I "http://localhost:$HARNESS_PORT/" >/dev/null 2>&1 && break
  sleep 0.2
done

NODE_TLS_REJECT_UNAUTHORIZED=0 node "$SCRIPT_DIR/browser.mjs" \
  --base-url "https://localhost:$HOST_TLS_PORT" \
  --harness-url "http://localhost:$HARNESS_PORT" \
  ${EXPECTED_PCR0:+--expected-pcr0 "$EXPECTED_PCR0"} \
  ${RUNTIME_TOKEN:+--runtime-token "$RUNTIME_TOKEN"} \
  | tee /tmp/browser.log || true
BROWSER_RC=${PIPESTATUS[0]}
if [ "$BROWSER_RC" -eq 0 ]; then pass "browser.mjs"; else fail "browser.mjs" "exit $BROWSER_RC"; fi

# Cleanup happens via trap.

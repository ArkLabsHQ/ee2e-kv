#!/usr/bin/env bash
# QEMU enclave launcher — lifted from
# introspector-enclave/test/run.sh:34-157 (boot_qemu function),
# extracted as a standalone script. See UPSTREAM.md for resync notes.
#
# Brings up the AF_VSOCK fabric (vhost-device-vsock + heartbeat), then
# boots the EIF in QEMU emulating a Nitro Enclave. Called two ways:
#
#   1. From the host-side supervisor's watchdog as ENCLAVE_START_CMD,
#      typically: ./boot.sh <path-to-eif>
#   2. Directly during dev (no supervisor) for a quick smoke test —
#      gvproxy/IMDS forwarding won't be available in this mode.
#
# Configurable via env:
#   GUEST_CID       (default 4)        — vsock CID of the QEMU guest
#   MEMORY          (default 4G)       — guest RAM
#   BOOT_TIMEOUT    (default 300s)     — wait for /health to respond
#   HOST_TLS_PORT   (default 8443)     — host port forwarded to enclave :443
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

eif_path="${1:?Usage: boot.sh <path-to-eif>}"

echo $$ > /tmp/enclave-boot.pid

if [ ! -f "$eif_path" ]; then
  echo "Error: EIF not found at $eif_path" >&2
  exit 1
fi
eif_path="$(realpath "$eif_path")"

guest_cid="${GUEST_CID:-4}"
memory="${MEMORY:-4G}"
vsock_socket="/tmp/vhost${guest_cid}.socket"
boot_timeout="${BOOT_TIMEOUT:-300}"
host_tls_port="${HOST_TLS_PORT:-8443}"

qemu_pid=""; hb_pid=""; vsock_pid=""

cleanup() {
  echo "" 2>/dev/null
  echo "=== Cleaning up ===" 2>/dev/null
  [ -n "$qemu_pid" ] && kill "$qemu_pid" 2>/dev/null && echo "  Stopped QEMU ($qemu_pid)" 2>/dev/null
  [ -n "$hb_pid" ] && kill "$hb_pid" 2>/dev/null && echo "  Stopped heartbeat ($hb_pid)" 2>/dev/null
  [ -n "$vsock_pid" ] && kill "$vsock_pid" 2>/dev/null && echo "  Stopped vhost-device-vsock ($vsock_pid)" 2>/dev/null
  rm -f "$vsock_socket" /tmp/enclave-boot.pid
}
trap cleanup EXIT

# Kill any stale processes from previous runs.
killall vhost-device-vsock 2>/dev/null || true
pkill -f heartbeat.py 2>/dev/null || true
sleep 0.5
rm -f "$vsock_socket"

if [ ! -e /dev/vsock ]; then
  echo "Error: /dev/vsock not found. Load vsock + vsock_loopback kernel modules:" >&2
  echo "  sudo modprobe vsock vsock_loopback" >&2
  exit 1
fi

echo "=== Starting vhost-device-vsock ==="
echo "  CID:        $guest_cid"
echo "  Socket:     $vsock_socket"
echo "  Forward:    CID 1 (loopback)"
vhost-device-vsock \
  --vm "guest-cid=${guest_cid},socket=${vsock_socket},forward-cid=1,forward-listen=9001+9002" &
vsock_pid=$!
sleep 1
if ! kill -0 "$vsock_pid" 2>/dev/null; then
  echo "Error: vhost-device-vsock failed to start" >&2
  exit 1
fi

echo "=== Starting heartbeat responder ==="
python3 "$SCRIPT_DIR/heartbeat.py" &
hb_pid=$!
sleep 0.5
if ! kill -0 "$hb_pid" 2>/dev/null; then
  echo "Error: heartbeat responder failed to start" >&2
  exit 1
fi

echo ""
echo "=== Booting QEMU enclave ==="
echo "  EIF:    $eif_path"
echo "  Memory: $memory"
if [ -e /dev/kvm ]; then
  accel="--enable-kvm"
  cpu_opt="-cpu host"
  echo "  KVM:    enabled"
else
  accel="-accel tcg"
  cpu_opt="-cpu max"
  echo "  KVM:    not available, using TCG (slow)"
fi
qemu-system-x86_64 \
  -M "nitro-enclave,vsock=c,id=test-enclave" \
  -kernel "$eif_path" \
  -nographic \
  -m "$memory" \
  $accel \
  $cpu_opt \
  -chardev "socket,id=c,path=${vsock_socket}" &
qemu_pid=$!
echo "  PID:    $qemu_pid"
echo ""

# Wait for the enclave to become ready. The supervisor's /health endpoint
# is exposed via gvproxy port-forward at $HOST_TLS_PORT.
echo "=== Waiting for enclave to boot (timeout: ${boot_timeout}s) ==="
seconds=0
while [ "$seconds" -lt "$boot_timeout" ]; do
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    echo "Error: QEMU exited unexpectedly" >&2
    wait "$qemu_pid" || true
    exit 1
  fi
  http_code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
    "https://localhost:${host_tls_port}/health" 2>/dev/null || echo "000")
  if [ "$http_code" = "200" ] || [ "$http_code" = "503" ]; then
    health=$(curl -sk --max-time 5 "https://localhost:${host_tls_port}/health" 2>/dev/null || echo "{}")
    echo "  Enclave responding (${seconds}s) — HTTP $http_code"
    echo "  Health: $health"
    echo ""
    echo "=== Enclave running ==="
    echo "  Health:        https://localhost:${host_tls_port}/health"
    echo "  Enclave info:  https://localhost:${host_tls_port}/v1/enclave-info"
    echo "  App API:       https://localhost:${host_tls_port}/api/info"
    wait "$qemu_pid"
    exit 0
  fi
  sleep 2
  seconds=$((seconds + 2))
done
echo "Error: Enclave did not become ready within ${boot_timeout}s" >&2
exit 1

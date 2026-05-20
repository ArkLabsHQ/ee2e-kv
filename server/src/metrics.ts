import { meter } from "./telemetry.js";

// Every instrument the server reports. Kept deliberately small — one counter
// plus one histogram per layer that matters (RPC, storage) and a bare counter
// for the two crypto paths. Anything finer is already visible as span
// attributes on the per-request trace.

export const rpcRequests = meter.createCounter("kv_rpc_requests_total", {
  description: "JSON-RPC requests dispatched, labelled by method and outcome.",
});

export const rpcDuration = meter.createHistogram("kv_rpc_request_duration_ms", {
  description: "JSON-RPC request handling latency.",
  unit: "ms",
});

export const storageOps = meter.createCounter("kv_storage_ops_total", {
  description: "Storage operations issued to the enclave runtime, by op and status.",
});

export const storageDuration = meter.createHistogram("kv_storage_op_duration_ms", {
  description: "Storage operation round-trip latency.",
  unit: "ms",
});

export const tokenVerify = meter.createCounter("kv_token_verify_total", {
  description: "Auth-token verification attempts, by outcome.",
});

export const webauthnCeremony = meter.createCounter("kv_webauthn_ceremony_total", {
  description: "WebAuthn ceremony steps, by op and outcome.",
});

// Stopwatch for histogram durations. The outcome label is usually only known
// after the work finishes, so callers time first and record once they can
// supply the final attributes.
export function startTimer(): () => number {
  const start = performance.now();
  return () => performance.now() - start;
}

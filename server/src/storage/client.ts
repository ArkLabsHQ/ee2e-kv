import { context, propagation, SpanKind, SpanStatusCode } from "@opentelemetry/api";
import { tracer } from "../telemetry.js";
import { storageOps, storageDuration, startTimer } from "../metrics.js";
import { log } from "../log.js";

export interface StorageClient {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, body: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

const DECODER = new TextDecoder();

export class HttpStorageClient implements StorageClient {
  constructor(private readonly baseUrl: string, private readonly token: string) {}

  async get(key: string): Promise<Uint8Array | null> {
    const res = await this.call("get", "GET", `${this.baseUrl}/v1/storage/${encodePath(key)}`, key);
    if (res.status === 404) return null;
    if (!res.ok) throw new StorageError(`GET ${key} -> ${res.status}`, res.status);
    return new Uint8Array(res.body);
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    const res = await this.call(
      "put",
      "PUT",
      `${this.baseUrl}/v1/storage/${encodePath(key)}`,
      key,
      body,
    );
    if (!res.ok) throw new StorageError(`PUT ${key} -> ${res.status}`, res.status);
  }

  async delete(key: string): Promise<void> {
    const res = await this.call(
      "delete",
      "DELETE",
      `${this.baseUrl}/v1/storage/${encodePath(key)}`,
      key,
    );
    if (!res.ok && res.status !== 404) {
      throw new StorageError(`DELETE ${key} -> ${res.status}`, res.status);
    }
  }

  async list(prefix: string): Promise<string[]> {
    const res = await this.call(
      "list",
      "GET",
      `${this.baseUrl}/v1/storage?prefix=${encodeURIComponent(prefix)}`,
      prefix,
    );
    if (!res.ok) throw new StorageError(`LIST ${prefix} -> ${res.status}`, res.status);
    const parsed = JSON.parse(DECODER.decode(res.body)) as string[] | null;
    return parsed ?? [];
  }

  // Single instrumented HTTP round-trip to the runtime storage API. Wraps the
  // fetch in a client span, injects the active trace context onto the wire,
  // and records the storage op counter + latency histogram.
  private async call(
    op: string,
    method: string,
    url: string,
    key: string,
    reqBody?: Uint8Array,
  ): Promise<{ status: number; ok: boolean; body: ArrayBuffer }> {
    return tracer.startActiveSpan(
      `storage.${op}`,
      {
        kind: SpanKind.CLIENT,
        attributes: { "storage.op": op, "storage.key": key, "http.request.method": method },
      },
      async (span) => {
        const elapsed = startTimer();
        const headers: Record<string, string> = { authorization: `Bearer ${this.token}` };
        if (reqBody) {
          headers["content-type"] = "application/octet-stream";
          span.setAttribute("http.request.body.size", reqBody.byteLength);
        }
        propagation.inject(context.active(), headers);

        try {
          const init: RequestInit = { method, headers };
          if (reqBody) init.body = reqBody as BodyInit;
          const res = await fetch(url, init);
          const body = await res.arrayBuffer();
          span.setAttributes({
            "http.response.status_code": res.status,
            "http.response.body.size": body.byteLength,
          });

          const status = res.status === 404 ? "not_found" : res.ok ? "ok" : "error";
          span.setAttribute("storage.op_status", status);
          if (status === "error") {
            span.setStatus({ code: SpanStatusCode.ERROR, message: `http ${res.status}` });
            log.warn("storage error", { op, key, status: res.status });
          }
          record(op, status, elapsed());
          return { status: res.status, ok: res.ok, body };
        } catch (err) {
          span.recordException(err as Error);
          span.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
          log.error("storage network", { op, key, err: String(err) });
          record(op, "error", elapsed());
          throw err;
        } finally {
          span.end();
        }
      },
    );
  }
}

export class StorageError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "StorageError";
  }
}

function record(op: string, status: string, ms: number): void {
  const labels = { op, status };
  storageOps.add(1, labels);
  storageDuration.record(ms, labels);
}

function encodePath(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

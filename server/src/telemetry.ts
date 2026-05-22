import { randomUUID } from "node:crypto";
import {
  metrics,
  trace,
  SpanStatusCode,
  type Attributes,
  type Meter,
  type Span,
  type Tracer,
} from "@opentelemetry/api";
import { logs, type Logger } from "@opentelemetry/api-logs";
import {
  CompositePropagator,
  W3CBaggagePropagator,
  W3CTraceContextPropagator,
} from "@opentelemetry/core";
import { defaultResource, resourceFromAttributes } from "@opentelemetry/resources";
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from "@opentelemetry/semantic-conventions";
import { BatchSpanProcessor, NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { MeterProvider, PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { BatchLogRecordProcessor, LoggerProvider } from "@opentelemetry/sdk-logs";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-proto";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-proto";
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-proto";

// Instrumentation scope — identifies this app as the source of every span,
// metric, and log record the SDK emits.
const SCOPE = "e2ee-kv-server";

const env = process.env;
const runtimeToken = env.ENCLAVE_RUNTIME_TOKEN ?? "";
const serviceVersion = env.APP_VERSION ?? "0.0.1";

// Telemetry is wired to the enclave runtime's OTLP collector, which is the
// only reachable network peer inside the enclave. With no runtime token there
// is nothing to authenticate to and nowhere to export — so OTEL stays off and
// every tracer/meter/logger handle below resolves to the API's built-in
// no-ops. `OTEL_ENABLED=false` forces the same path for local development.
export const telemetryEnabled = env.OTEL_ENABLED !== "false" && runtimeToken.length > 0;

let tracerProvider: NodeTracerProvider | undefined;
let meterProvider: MeterProvider | undefined;
let loggerProvider: LoggerProvider | undefined;

if (telemetryEnabled) {
  // The OTLP endpoint is the runtime supervisor. The OTEL SDK appends the
  // standard /v1/{traces,metrics,logs} signal paths to this base.
  const endpoint = (
    env.OTEL_EXPORTER_OTLP_ENDPOINT ??
    env.ENCLAVE_PROXY_PORT ??
    "http://127.0.0.1:7073"
  ).replace(/\/+$/, "");
  const headers = { Authorization: `Bearer ${runtimeToken}` };
  const metricIntervalMs = Number(env.OTEL_METRIC_EXPORT_INTERVAL_MS) || 5000;

  const resource = defaultResource().merge(
    resourceFromAttributes({
      [ATTR_SERVICE_NAME]: env.OTEL_SERVICE_NAME ?? SCOPE,
      [ATTR_SERVICE_VERSION]: serviceVersion,
      "service.instance.id": randomUUID(),
    }),
  );

  tracerProvider = new NodeTracerProvider({
    resource,
    spanProcessors: [
      new BatchSpanProcessor(new OTLPTraceExporter({ url: `${endpoint}/v1/traces`, headers })),
    ],
  });
  // register() installs the global tracer provider, the async-context manager
  // (so getActiveSpan() works across awaits), and the propagators below.
  tracerProvider.register({
    propagator: new CompositePropagator({
      propagators: [new W3CTraceContextPropagator(), new W3CBaggagePropagator()],
    }),
  });

  meterProvider = new MeterProvider({
    resource,
    readers: [
      new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: `${endpoint}/v1/metrics`, headers }),
        exportIntervalMillis: metricIntervalMs,
      }),
    ],
  });
  metrics.setGlobalMeterProvider(meterProvider);

  loggerProvider = new LoggerProvider({
    resource,
    processors: [
      new BatchLogRecordProcessor(new OTLPLogExporter({ url: `${endpoint}/v1/logs`, headers })),
    ],
  });
  logs.setGlobalLoggerProvider(loggerProvider);
}

// Resolved after registration so they bind to the real providers when
// telemetry is enabled, and to API no-ops otherwise.
export const tracer: Tracer = trace.getTracer(SCOPE, serviceVersion);
export const meter: Meter = metrics.getMeter(SCOPE, serviceVersion);
export const otelLogger: Logger = logs.getLogger(SCOPE, serviceVersion);

// Run an async unit of work inside an active span: records the exception and
// marks the span errored if it throws, and always ends the span.
export async function withSpan<T>(
  name: string,
  attributes: Attributes,
  fn: (span: Span) => Promise<T>,
): Promise<T> {
  return tracer.startActiveSpan(name, { attributes }, async (span) => {
    try {
      return await fn(span);
    } catch (err) {
      span.recordException(err as Error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
      throw err;
    } finally {
      span.end();
    }
  });
}

// Flush buffered spans/metrics/logs before the process exits — without this,
// the last few seconds of telemetry are lost on shutdown.
export async function shutdownTelemetry(): Promise<void> {
  if (!telemetryEnabled) return;
  await Promise.allSettled([
    tracerProvider?.shutdown(),
    meterProvider?.shutdown(),
    loggerProvider?.shutdown(),
  ]);
}

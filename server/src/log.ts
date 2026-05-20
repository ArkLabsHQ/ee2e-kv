import { SeverityNumber, type LogAttributes } from "@opentelemetry/api-logs";
import { otelLogger } from "./telemetry.js";

type Level = "debug" | "info" | "warn" | "error";

const RANK: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };
const SEVERITY: Record<Level, SeverityNumber> = {
  debug: SeverityNumber.DEBUG,
  info: SeverityNumber.INFO,
  warn: SeverityNumber.WARN,
  error: SeverityNumber.ERROR,
};


const threshold = RANK[(process.env.OTEL_LOG_LEVEL as Level) ?? "info"] ?? RANK.info;

function emit(level: Level, msg: string, fields?: Record<string, unknown>): void {
  if (RANK[level] < threshold) return;

  const line = { level, ts: new Date().toISOString(), msg, ...fields };
  const out = level === "error" || level === "warn" ? process.stderr : process.stdout;
  out.write(JSON.stringify(line) + "\n");


  otelLogger.emit({
    severityNumber: SEVERITY[level],
    severityText: level.toUpperCase(),
    body: msg,
    attributes: (fields ?? {}) as LogAttributes,
  });
}

export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => emit("debug", msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => emit("info", msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => emit("warn", msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => emit("error", msg, fields),
};

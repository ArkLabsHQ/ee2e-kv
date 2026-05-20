import { trace } from "@opentelemetry/api";
import type { StorageClient } from "../storage/client.js";
import { kvKey, kvUserPrefix } from "../storage/keys.js";
import { decode, encode, type KvRecord } from "./codec.js";

export interface KvListItem {
  key_id: string;
  name_ct: string;
  version: number;
}

export class KvService {
  constructor(private readonly storage: StorageClient) {}

  async get(userId: string, keyId: string): Promise<KvRecord | null> {
    const raw = await this.storage.get(kvKey(userId, keyId));
    if (!raw) return null;
    return decode(raw);
  }

  async put(
    userId: string,
    keyId: string,
    valueB64: string,
    nameCtB64: string,
    expectedVersion: number,
  ): Promise<{ kind: "ok"; new_version: number } | { kind: "conflict"; current_version: number }> {
    const current = await this.get(userId, keyId);
    const currentVersion = current?.version ?? 0;
    if (currentVersion !== expectedVersion) {

      trace.getActiveSpan()?.setAttributes({
        "kv.outcome": "conflict",
        "kv.current_version": currentVersion,
      });
      return { kind: "conflict", current_version: currentVersion };
    }
    const next: KvRecord = {
      version: currentVersion + 1,
      value: valueB64,
      name_ct: nameCtB64,
      updated_at: Date.now(),
    };
    await this.storage.put(kvKey(userId, keyId), encode(next));
    return { kind: "ok", new_version: next.version };
  }

  async del(
    userId: string,
    keyId: string,
    expectedVersion: number,
  ): Promise<{ kind: "ok" } | { kind: "not_found" } | { kind: "conflict"; current_version: number }> {
    const current = await this.get(userId, keyId);
    if (!current) return { kind: "not_found" };
    if (current.version !== expectedVersion) {
      trace.getActiveSpan()?.setAttributes({
        "kv.outcome": "conflict",
        "kv.current_version": current.version,
      });
      return { kind: "conflict", current_version: current.version };
    }
    await this.storage.delete(kvKey(userId, keyId));
    return { kind: "ok" };
  }

  async list(
    userId: string,
    cursor: string | undefined,
    limit: number,
  ): Promise<{ items: KvListItem[]; next_cursor?: string }> {
    const prefix = kvUserPrefix(userId);
    const allKeys = (await this.storage.list(prefix)).filter((k) => k.startsWith(prefix)).sort();
    const startIdx = cursor ? allKeys.findIndex((k) => k > cursor) : 0;
    const slice = allKeys.slice(startIdx === -1 ? allKeys.length : startIdx, (startIdx === -1 ? 0 : startIdx) + limit);

    const items: KvListItem[] = [];
    for (const fullKey of slice) {
      const raw = await this.storage.get(fullKey);
      if (!raw) continue;
      const rec = decode(raw);
      const keyId = fullKey.slice(prefix.length);
      items.push({ key_id: keyId, name_ct: rec.name_ct, version: rec.version });
    }
    const nextCursor = slice.length === limit ? slice[slice.length - 1] : undefined;

    trace.getActiveSpan()?.setAttributes({
      "kv.scanned": allKeys.length,
      "kv.returned": items.length,
    });
    return nextCursor ? { items, next_cursor: nextCursor } : { items };
  }
}

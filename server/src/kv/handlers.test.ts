import { describe, expect, it } from "vitest";
import { KvService } from "./handlers.js";
import type { StorageClient } from "../storage/client.js";

class MemStorage implements StorageClient {
  store = new Map<string, Uint8Array>();
  async get(key: string) { return this.store.get(key) ?? null; }
  async put(key: string, body: Uint8Array) { this.store.set(key, body); }
  async delete(key: string) { this.store.delete(key); }
  async list(prefix: string) { return [...this.store.keys()].filter((k) => k.startsWith(prefix)); }
}

const value = "ABC=";
const nameCt = "DEF=";

describe("KvService", () => {
  it("put creates v1 from v0", async () => {
    const kv = new KvService(new MemStorage());
    const r = await kv.put("u1", "K".repeat(32), value, nameCt, 0);
    expect(r).toEqual({ kind: "ok", new_version: 1 });
  });

  it("put returns conflict on stale version", async () => {
    const kv = new KvService(new MemStorage());
    await kv.put("u1", "K".repeat(32), value, nameCt, 0);
    const r = await kv.put("u1", "K".repeat(32), value, nameCt, 0);
    expect(r).toEqual({ kind: "conflict", current_version: 1 });
  });

  it("put bumps version on correct expected_version", async () => {
    const kv = new KvService(new MemStorage());
    await kv.put("u1", "K".repeat(32), value, nameCt, 0);
    const r = await kv.put("u1", "K".repeat(32), value, nameCt, 1);
    expect(r).toEqual({ kind: "ok", new_version: 2 });
  });

  it("get returns null for missing key", async () => {
    const kv = new KvService(new MemStorage());
    const r = await kv.get("u1", "M".repeat(32));
    expect(r).toBeNull();
  });

  it("del returns not_found if absent", async () => {
    const kv = new KvService(new MemStorage());
    const r = await kv.del("u1", "M".repeat(32), 0);
    expect(r).toEqual({ kind: "not_found" });
  });

  it("del refuses on version mismatch", async () => {
    const kv = new KvService(new MemStorage());
    await kv.put("u1", "K".repeat(32), value, nameCt, 0);
    const r = await kv.del("u1", "K".repeat(32), 99);
    expect(r).toEqual({ kind: "conflict", current_version: 1 });
  });

  it("list scopes to user prefix", async () => {
    const kv = new KvService(new MemStorage());
    await kv.put("u1", "A".repeat(32), value, nameCt, 0);
    await kv.put("u2", "B".repeat(32), value, nameCt, 0);
    const r = await kv.list("u1", undefined, 100);
    expect(r.items).toHaveLength(1);
    expect(r.items[0]?.key_id).toBe("A".repeat(32));
  });
});

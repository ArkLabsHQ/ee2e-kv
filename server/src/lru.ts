interface Entry<V> {
  value: V;
  expiresAt: number;
}

export class TtlLru<K, V> {
  private readonly map = new Map<K, Entry<V>>();
  constructor(private readonly maxSize: number, private readonly ttlMs: number) {}

  get(key: K): V | undefined {
    const e = this.map.get(key);
    if (!e) return undefined;
    if (e.expiresAt <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, e);
    return e.value;
  }

  has(key: K): boolean {
    return this.get(key) !== undefined;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { value, expiresAt: Date.now() + this.ttlMs });
    while (this.map.size > this.maxSize) {
      const first = this.map.keys().next();
      if (first.done) break;
      this.map.delete(first.value);
    }
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  consume(key: K): V | undefined {
    const v = this.get(key);
    if (v !== undefined) this.map.delete(key);
    return v;
  }

  size(): number {
    return this.map.size;
  }
}

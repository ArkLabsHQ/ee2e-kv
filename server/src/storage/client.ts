export interface StorageClient {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, body: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

export class HttpStorageClient implements StorageClient {
  constructor(private readonly baseUrl: string, private readonly token: string) {}

  private headers(extra: Record<string, string> = {}): HeadersInit {
    return { authorization: `Bearer ${this.token}`, ...extra };
  }

  async get(key: string): Promise<Uint8Array | null> {
    const res = await fetch(`${this.baseUrl}/v1/storage/${encodePath(key)}`, {
      method: "GET",
      headers: this.headers(),
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new StorageError(`GET ${key} -> ${res.status}`, res.status);
    const buf = await res.arrayBuffer();
    return new Uint8Array(buf);
  }

  async put(key: string, body: Uint8Array): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v1/storage/${encodePath(key)}`, {
      method: "PUT",
      headers: this.headers({ "content-type": "application/octet-stream" }),
      body: body as BodyInit,
    });
    if (!res.ok) throw new StorageError(`PUT ${key} -> ${res.status}`, res.status);
  }

  async delete(key: string): Promise<void> {
    const res = await fetch(`${this.baseUrl}/v1/storage/${encodePath(key)}`, {
      method: "DELETE",
      headers: this.headers(),
    });
    if (!res.ok && res.status !== 404) throw new StorageError(`DELETE ${key} -> ${res.status}`, res.status);
  }

  async list(prefix: string): Promise<string[]> {
    const res = await fetch(`${this.baseUrl}/v1/storage?prefix=${encodeURIComponent(prefix)}`, {
      method: "GET",
      headers: this.headers(),
    });
    if (!res.ok) throw new StorageError(`LIST ${prefix} -> ${res.status}`, res.status);
    const body = (await res.json()) as string[] | null;
    return body ?? [];
  }
}

export class StorageError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "StorageError";
  }
}

function encodePath(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

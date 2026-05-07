import { RpcResponse, type RpcError } from "@e2ee-kv/protocol";
import { verifySchnorrSignature } from "./schnorr.js";

export interface RpcClientOpts {
  baseUrl?: string;
  /** Hex-encoded pinned attestation pubkey, or `null` to skip response-signature verification (dev only). */
  attestationPubkeyHex: string | null;
  authToken?: () => string | null;
}

let nextId = 1;

export class RpcCallError extends Error {
  constructor(public readonly rpcError: RpcError) {
    super(`${rpcError.code}: ${rpcError.message}`);
    this.name = "RpcCallError";
  }
}

export class RpcClient {
  constructor(private readonly opts: RpcClientOpts) {}

  async call<T>(method: string, params: unknown = {}): Promise<T> {
    const reqBody = {
      jsonrpc: "2.0" as const,
      method,
      params,
      id: nextId++,
    };
    const headers: Record<string, string> = { "content-type": "application/json" };
    const tok = this.opts.authToken?.();
    if (tok) headers["authorization"] = `Bearer ${tok}`;
    const baseUrl = this.opts.baseUrl ?? "";
    const res = await fetch(`${baseUrl}/api/rpc`, {
      method: "POST",
      headers,
      body: JSON.stringify(reqBody),
    });
    const bodyBytes = new Uint8Array(await res.arrayBuffer());
    if (this.opts.attestationPubkeyHex !== null) {
      await this.verifyResponseSignature(bodyBytes, res.headers);
    }
    const parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as unknown;
    const rpc = RpcResponse.parse(parsed);
    if (rpc.error) throw new RpcCallError(rpc.error);
    return rpc.result as T;
  }

  private async verifyResponseSignature(body: Uint8Array, headers: Headers): Promise<void> {
    const pinned = this.opts.attestationPubkeyHex;
    if (pinned === null) return;
    const sigHex = headers.get("x-attestation-signature");
    const pubkeyHex = headers.get("x-attestation-pubkey");
    if (!sigHex || !pubkeyHex) throw new Error("response missing attestation signature headers");
    if (pubkeyHex.toLowerCase() !== pinned.toLowerCase()) {
      throw new Error(
        `response signed with unpinned key (got ${pubkeyHex}, pinned ${pinned})`,
      );
    }
    const ok = verifySchnorrSignature(body, sigHex, pubkeyHex);
    if (!ok) throw new Error("response signature verification failed");
  }
}

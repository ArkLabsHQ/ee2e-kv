import { z } from "zod";
import { verifySchnorrSignature } from "./schnorr.js";

/**
 * Minimal JSON-RPC 2.0 envelope. Apps with their own typed protocol package
 * are free to redefine this — RpcClient only validates the envelope shape and
 * passes `result` back as `unknown`, so the caller can narrow it.
 */
const RpcId = z.union([z.string(), z.number(), z.null()]);

export const JsonRpcError = z.object({
  code: z.number().int(),
  message: z.string(),
  data: z.unknown().optional(),
});
export type JsonRpcError = z.infer<typeof JsonRpcError>;

export const JsonRpcResponse = z.object({
  jsonrpc: z.literal("2.0"),
  id: RpcId,
  result: z.unknown().optional(),
  error: JsonRpcError.optional(),
});
export type JsonRpcResponse = z.infer<typeof JsonRpcResponse>;

export interface RpcClientOpts {
  baseUrl?: string;
  /**
   * Path the JSON-RPC endpoint is mounted at. Defaults to `/api/rpc` so
   * apps that follow the framework convention need no configuration.
   */
  rpcPath?: string;
  /** Hex-encoded pinned attestation pubkey, or `null` to skip response-signature verification (dev only). */
  attestationPubkeyHex: string | null;
  authToken?: () => string | null;
}

let nextId = 1;

export class RpcCallError extends Error {
  constructor(public readonly rpcError: JsonRpcError) {
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
    const rpcPath = this.opts.rpcPath ?? "/api/rpc";
    const res = await fetch(`${baseUrl}${rpcPath}`, {
      method: "POST",
      headers,
      body: JSON.stringify(reqBody),
    });
    const bodyBytes = new Uint8Array(await res.arrayBuffer());
    if (this.opts.attestationPubkeyHex !== null) {
      await this.verifyResponseSignature(bodyBytes, res.headers);
    }
    const parsed = JSON.parse(new TextDecoder().decode(bodyBytes)) as unknown;
    const rpc = JsonRpcResponse.parse(parsed);
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

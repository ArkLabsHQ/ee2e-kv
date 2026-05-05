import { z } from "zod";

export const RpcId = z.union([z.string(), z.number(), z.null()]);
export type RpcId = z.infer<typeof RpcId>;

export const RpcRequest = z.object({
  jsonrpc: z.literal("2.0"),
  method: z.string(),
  params: z.unknown().optional(),
  id: RpcId.optional(),
});
export type RpcRequest = z.infer<typeof RpcRequest>;

export const RpcError = z.object({
  code: z.number().int(),
  message: z.string(),
  data: z.unknown().optional(),
});
export type RpcError = z.infer<typeof RpcError>;

export const RpcResponse = z.object({
  jsonrpc: z.literal("2.0"),
  id: RpcId,
  result: z.unknown().optional(),
  error: RpcError.optional(),
});
export type RpcResponse = z.infer<typeof RpcResponse>;

export const ErrorCode = {
  parse_error: -32700,
  invalid_request: -32600,
  method_not_found: -32601,
  invalid_params: -32602,
  internal_error: -32603,
  unauthorized: -32001,
  forbidden: -32002,
  not_found: -32010,
  version_conflict: -32011,
  webauthn_failed: -32020,
  nonce_invalid_or_used: -32021,
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

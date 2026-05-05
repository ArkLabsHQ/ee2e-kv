import { z } from "zod";

const Base64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, "base64");
const Base64Url = z.string().regex(/^[A-Za-z0-9_-]*$/, "base64url");
const Hex = z.string().regex(/^[0-9a-f]*$/i, "hex");

export const SessionBeginParams = z.object({}).strict();
export const SessionBeginResult = z.object({
  server_nonce: Base64,
  expires_at: z.number().int().positive(),
});

export const RegisterBeginParams = z.object({
  user_handle: Base64.optional(),
}).strict();
export const RegisterBeginResult = z.object({
  server_nonce: Base64,
  options: z.unknown(),
});

export const RegisterFinishParams = z.object({
  server_nonce: Base64,
  credential: z.unknown(),
}).strict();
export const RegisterFinishResult = z.object({
  user_id: Base64,
  credential_id: Base64Url,
  auth_token: z.string(),
  expires_at: z.number().int().positive(),
});

export const AssertBeginParams = z.object({
  user_id: Base64.optional(),
}).strict();
export const AssertBeginResult = z.object({
  server_nonce: Base64,
  options: z.unknown(),
});

export const AssertFinishParams = z.object({
  server_nonce: Base64,
  credential: z.unknown(),
}).strict();
export const AssertFinishResult = z.object({
  user_id: Base64,
  auth_token: z.string(),
  expires_at: z.number().int().positive(),
});

export const CredentialsListParams = z.object({}).strict();
export const CredentialsListResult = z.object({
  credentials: z.array(z.object({
    id: Base64Url,
    created_at: z.number().int(),
    transports: z.array(z.string()).optional(),
  })),
});

export const CredentialsDeleteParams = z.object({
  credential_id: Base64Url,
}).strict();
export const CredentialsDeleteResult = z.object({ ok: z.literal(true) });

const KeyId = z.string().regex(/^[A-Z2-7]{32}$/, "base32 key_id");

export const KvGetParams = z.object({ key_id: KeyId }).strict();
export const KvGetResult = z.object({
  value: Base64,
  name_ct: Base64,
  version: z.number().int().nonnegative(),
});

export const KvPutParams = z.object({
  key_id: KeyId,
  value: Base64,
  name_ct: Base64,
  expected_version: z.number().int().nonnegative(),
}).strict();
export const KvPutResult = z.object({
  new_version: z.number().int().positive(),
});

export const KvDelParams = z.object({
  key_id: KeyId,
  expected_version: z.number().int().nonnegative(),
}).strict();
export const KvDelResult = z.object({ ok: z.literal(true) });

export const KvListParams = z.object({
  cursor: z.string().optional(),
  limit: z.number().int().positive().max(1000).optional(),
}).strict();
export const KvListResult = z.object({
  items: z.array(z.object({
    key_id: KeyId,
    name_ct: Base64,
    version: z.number().int().nonnegative(),
  })),
  next_cursor: z.string().optional(),
});

export const KvBatchGetParams = z.object({
  key_ids: z.array(KeyId).min(1).max(256),
}).strict();
export const KvBatchGetResult = z.object({
  results: z.record(KeyId, z.union([
    z.object({
      value: Base64,
      name_ct: Base64,
      version: z.number().int().nonnegative(),
    }),
    z.object({ error: z.literal("not_found") }),
  ])),
});

export const KvBatchPutItem = z.object({
  key_id: KeyId,
  value: Base64,
  name_ct: Base64,
  expected_version: z.number().int().nonnegative(),
});
export const KvBatchPutParams = z.object({
  items: z.array(KvBatchPutItem).min(1).max(256),
}).strict();
export const KvBatchPutResult = z.object({
  results: z.array(z.union([
    z.object({ new_version: z.number().int().positive() }),
    z.object({ error: z.string(), data: z.unknown().optional() }),
  ])),
});

export type Method =
  | "session.begin"
  | "auth.webauthn.register.begin"
  | "auth.webauthn.register.finish"
  | "auth.webauthn.assert.begin"
  | "auth.webauthn.assert.finish"
  | "auth.credentials.list"
  | "auth.credentials.delete"
  | "kv.get"
  | "kv.put"
  | "kv.del"
  | "kv.list"
  | "kv.batch_get"
  | "kv.batch_put";

export const MethodSchemas = {
  "session.begin": { params: SessionBeginParams, result: SessionBeginResult, auth: false },
  "auth.webauthn.register.begin": { params: RegisterBeginParams, result: RegisterBeginResult, auth: "optional" },
  "auth.webauthn.register.finish": { params: RegisterFinishParams, result: RegisterFinishResult, auth: false },
  "auth.webauthn.assert.begin": { params: AssertBeginParams, result: AssertBeginResult, auth: false },
  "auth.webauthn.assert.finish": { params: AssertFinishParams, result: AssertFinishResult, auth: false },
  "auth.credentials.list": { params: CredentialsListParams, result: CredentialsListResult, auth: true },
  "auth.credentials.delete": { params: CredentialsDeleteParams, result: CredentialsDeleteResult, auth: true },
  "kv.get": { params: KvGetParams, result: KvGetResult, auth: true },
  "kv.put": { params: KvPutParams, result: KvPutResult, auth: true },
  "kv.del": { params: KvDelParams, result: KvDelResult, auth: true },
  "kv.list": { params: KvListParams, result: KvListResult, auth: true },
  "kv.batch_get": { params: KvBatchGetParams, result: KvBatchGetResult, auth: true },
  "kv.batch_put": { params: KvBatchPutParams, result: KvBatchPutResult, auth: true },
} as const satisfies Record<Method, { params: z.ZodTypeAny; result: z.ZodTypeAny; auth: true | false | "optional" }>;

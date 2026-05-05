import { z } from "zod";

export const KvRecord = z.object({
  version: z.number().int().nonnegative(),
  value: z.string(),     // base64 of (nonce || ct||tag), opaque to server
  name_ct: z.string(),   // base64, opaque to server
  updated_at: z.number().int(),
});
export type KvRecord = z.infer<typeof KvRecord>;

export function encode(record: KvRecord): Uint8Array {
  return Buffer.from(JSON.stringify(record), "utf8");
}

export function decode(raw: Uint8Array): KvRecord {
  return KvRecord.parse(JSON.parse(Buffer.from(raw).toString("utf8")));
}

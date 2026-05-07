import { z } from "zod";

export const RpInfo = z.object({
  id: z.string(),
  name: z.string(),
  origin: z.string(),
});

export const ApiInfo = z.object({
  version: z.string(),
  providers: z.array(z.string()),
  rp: RpInfo,
});
export type ApiInfo = z.infer<typeof ApiInfo>;

import type { ApiInfo } from "@e2ee-kv/protocol";

export function buildApiInfo(input: {
  version: string;
  rp: { id: string; name: string; origin: string };
}): ApiInfo {
  return {
    version: input.version,
    providers: ["webauthn"],
    rp: input.rp,
  };
}

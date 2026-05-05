import type { AuthClaims } from "../auth/jwt.js";

export interface Ctx {
  auth: AuthClaims | null;
}

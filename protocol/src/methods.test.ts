import { describe, expect, it } from "vitest";
import { ErrorCode, MethodSchemas } from "./index.js";

describe("MethodSchemas", () => {
  it("exposes every documented method", () => {
    const required = [
      "session.begin",
      "auth.webauthn.register.begin",
      "auth.webauthn.register.finish",
      "auth.webauthn.assert.begin",
      "auth.webauthn.assert.finish",
      "auth.credentials.list",
      "auth.credentials.delete",
      "kv.get",
      "kv.put",
      "kv.del",
      "kv.list",
      "kv.batch_get",
      "kv.batch_put",
    ];
    for (const m of required) {
      expect(MethodSchemas).toHaveProperty(m);
    }
  });

  it("kv.put requires a 32-char base32 key_id", () => {
    expect(() =>
      MethodSchemas["kv.put"].params.parse({
        key_id: "too-short",
        value: "A",
        name_ct: "B",
        expected_version: 0,
      }),
    ).toThrow();
    const ok = MethodSchemas["kv.put"].params.parse({
      key_id: "A".repeat(32),
      value: "AAAA",
      name_ct: "BBBB",
      expected_version: 0,
    });
    expect(ok.expected_version).toBe(0);
  });

  it("error codes match the spec", () => {
    expect(ErrorCode.unauthorized).toBe(-32001);
    expect(ErrorCode.forbidden).toBe(-32002);
    expect(ErrorCode.not_found).toBe(-32010);
    expect(ErrorCode.version_conflict).toBe(-32011);
    expect(ErrorCode.webauthn_failed).toBe(-32020);
    expect(ErrorCode.nonce_invalid_or_used).toBe(-32021);
  });
});

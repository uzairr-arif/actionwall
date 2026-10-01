import { describe, expect, it } from "vitest";
import * as path from "node:path";
import { loadPolicy, policySchema, PolicyValidationError } from "../src/core/policy.js";

const POLICIES = path.resolve(process.cwd(), "policies");

describe("policy loader", () => {
  it("returns the built-in default policy when no path is given", () => {
    const policy = loadPolicy();
    expect(policy.name).toBe("default");
    expect(policy.version).toBe(1);
    expect(policy.file_policy.max_bulk_delete).toBe(10);
    expect(policy.risk_thresholds.block).toEqual(["HIGH", "CRITICAL"]);
    expect(policy.fail_closed).toBe(true);
    expect(policy.file_policy.protected_paths.some((r) => r.path === "**/.env")).toBe(true);
  });

  it("loads the shipped policy presets", () => {
    const strict = loadPolicy(path.join(POLICIES, "strict.yaml"));
    expect(strict.name).toBe("strict");
    expect(strict.tools.default).toBe("deny");
    expect(strict.url_policy.allowed_domains).toContain("api.github.com");
    expect(strict.injection.hits_for_high).toBe(1);

    const readonly = loadPolicy(path.join(POLICIES, "readonly.yaml"));
    expect(readonly.file_policy.protected_paths[0]!.path).toBe("**");
    expect(readonly.file_policy.protected_paths[0]!.permissions).toEqual(["readonly"]);

    const dflt = loadPolicy(path.join(POLICIES, "default.yaml"));
    expect(dflt.file_policy.max_bulk_delete).toBe(10);
  });

  it("fails on missing files with a readable error", () => {
    expect(() => loadPolicy(path.join(POLICIES, "missing.yaml"))).toThrow(/Cannot read policy/);
  });

  it("validates documents against the schema", () => {
    const bad = policySchema.safeParse({ version: 1, risk_thresholds: { block: ["NOPE"] } });
    expect(bad.success).toBe(false);

    const good = policySchema.safeParse({ version: 1 });
    expect(good.success).toBe(true);
  });

  it("PolicyValidationError formats issues with paths", () => {
    const err = new PolicyValidationError("test.yaml", [
      {
        code: "invalid_type",
        expected: "string",
        received: "number",
        path: ["name"],
        message: "Expected string, received number",
      } as never,
    ]);
    expect(err.message).toContain("test.yaml");
    expect(err.message).toContain("name");
  });
});

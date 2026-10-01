import { describe, expect, it } from "vitest";
import { toolPermissionsScanner } from "../src/scanners/toolPermissions.js";
import { toolAction, defaultPolicy, type PolicyDoc } from "./helpers.js";

const policy = defaultPolicy();

describe("toolPermissions scanner", () => {
  it("allows everything under the default allow-by-default policy", () => {
    expect(toolPermissionsScanner.scan(toolAction("anything.goes", {}), policy)).toEqual([]);
  });

  it("blocks tools on the deny list regardless of allow entries", () => {
    const p: PolicyDoc = { ...policy, tools: { ...policy.tools, allow: ["shell"], deny: ["shell"] } };
    const findings = toolPermissionsScanner.scan(toolAction("shell", { command: "ls" }), p);
    expect(findings[0]!.ruleId).toBe("TP-TOOL-DENIED");
    expect(findings[0]!.severity).toBe("HIGH");
  });

  it("implements deny-by-default with wildcard allows", () => {
    const p: PolicyDoc = {
      ...policy,
      tools: { ...policy.tools, default: "deny", allow: ["file.*", "web.search"] },
    };
    expect(toolPermissionsScanner.scan(toolAction("file.read", { path: "x" }), p)).toEqual([]);
    expect(toolPermissionsScanner.scan(toolAction("web.search", { q: "x" }), p)).toEqual([]);
    const flagged = toolPermissionsScanner.scan(toolAction("shell", { command: "ls" }), p);
    expect(flagged[0]!.ruleId).toBe("TP-NOT-ALLOWED");
    expect(flagged[0]!.severity).toBe("MEDIUM");
  });

  it("applies per-agent overrides", () => {
    const p: PolicyDoc = {
      ...policy,
      tools: {
        default: "allow",
        allow: [],
        deny: [],
        agents: {
          "intern-agent": { default: "deny", allow: ["file.read"], deny: [] },
        },
      },
    };
    const intern = (tool: string, params: Record<string, unknown>) => ({ ...toolAction(tool, params), agentId: "intern-agent" });
    expect(toolPermissionsScanner.scan(intern("file.read", { path: "x" }), p)).toEqual([]);
    expect(toolPermissionsScanner.scan(intern("shell", { command: "ls" }), p)).toHaveLength(1);

    // Other agents are unaffected by the intern's restrictions.
    expect(toolPermissionsScanner.scan(toolAction("shell", { command: "ls" }), p)).toEqual([]);
  });
});

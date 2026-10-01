/**
 * Tool-permission scanner: the coarse gate before content-level scanners run.
 * Implements allow/deny lists with wildcards ("file.*", "admin.*"), an
 * optional deny-by-default mode, and per-agent overrides.
 */

import type { Action, Finding, PolicyDoc, Scanner } from "../core/types.js";

interface ToolRules {
  default: "allow" | "deny";
  allow: string[];
  deny: string[];
}

function wildcardMatch(pattern: string, tool: string): boolean {
  if (!pattern.includes("*")) return pattern === tool;
  const re = new RegExp(
    `^${pattern.split("*").map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`
  );
  return re.test(tool);
}

function listMatches(list: string[], tool: string): boolean {
  return list.some((p) => wildcardMatch(p, tool));
}

export const toolPermissionsScanner: Scanner = {
  name: "toolPermissions",

  scan(action: Action, policy: PolicyDoc): Finding[] {
    // Per-agent config replaces the global lists when present.
    const agentOverride = policy.tools.agents[action.agentId];
    const rules: ToolRules = agentOverride
      ? {
          default: agentOverride.default ?? policy.tools.default,
          allow: agentOverride.allow,
          deny: agentOverride.deny,
        }
      : {
          default: policy.tools.default,
          allow: policy.tools.allow,
          deny: policy.tools.deny,
        };

    // Deny always wins over allow — explicit blocks cannot be bypassed by
    // adding the tool to the allowlist.
    if (listMatches(rules.deny, action.tool)) {
      return [
        {
          scanner: this.name,
          ruleId: "TP-TOOL-DENIED",
          severity: "HIGH",
          title: `Tool "${action.tool}" is denied by policy`,
          reason: `The tool "${action.tool}" appears in the deny list for agent "${action.agentId}". Deny rules always take precedence over allow rules.`,
          policyRef: agentOverride ? "tools.agents[].deny" : "tools.deny",
        },
      ];
    }

    if (rules.default === "deny" && !listMatches(rules.allow, action.tool)) {
      return [
        {
          scanner: this.name,
          ruleId: "TP-NOT-ALLOWED",
          severity: "MEDIUM",
          title: `Tool "${action.tool}" is not in the allowlist`,
          reason: `This policy runs deny-by-default and "${action.tool}" is not on the allow list for agent "${action.agentId}". Escalating to a human before first use.`,
          policyRef: agentOverride ? "tools.agents[].default/allow" : "tools.default/allow",
        },
      ];
    }

    return [];
  },
};

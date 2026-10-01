/**
 * Policy loading + validation.
 *
 * A policy is a YAML (or JSON) document validated with zod. Every section has
 * safe defaults, so `loadPolicy()` with no path yields the built-in baseline
 * (the same defaults shipped in policies/default.yaml).
 */

import { readFileSync } from "node:fs";
import { z } from "zod";
import { parse as parseYaml } from "yaml";
import type { PolicyDoc, RiskLevel } from "./types.js";

export const riskLevelSchema = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/**
 * `z.object(...).default({})` would short-circuit in zod v3 (defaults are not
 * re-parsed, so nested defaults would be lost). This wrapper preprocesses a
 * missing section into `{}`, which the object schema then parses normally —
 * filling in every nested default.
 */
const section = <T extends z.ZodObject<any>>(schema: T) =>
  z.preprocess((v) => (v === undefined ? {} : v), schema);

const pathRuleSchema = z.object({
  path: z.string().min(1),
  permissions: z.array(z.enum(["deny", "readonly", "allow"])).default(["deny"]),
  description: z.string().optional(),
});

const secretPatternSchema = z.object({
  name: z.string().min(1),
  regex: z.string().min(1),
  severity: riskLevelSchema.default("HIGH"),
});

const agentToolsSchema = z.object({
  default: z.enum(["allow", "deny"]).optional(),
  allow: z.array(z.string()).default([]),
  deny: z.array(z.string()).default([]),
});

export const policySchema = z.object({
  version: z.literal(1).default(1),
  name: z.string().default("default"),
  description: z.string().optional(),
  fail_closed: z.boolean().default(true),
  risk_thresholds: section(
    z.object({
      block: z.array(riskLevelSchema).default(["HIGH", "CRITICAL"]),
      ask: z.array(riskLevelSchema).default(["MEDIUM"]),
    })
  ),
  tools: section(
    z.object({
      default: z.enum(["allow", "deny"]).default("allow"),
      allow: z.array(z.string()).default([]),
      deny: z.array(z.string()).default([]),
      agents: z.record(z.string(), agentToolsSchema).default({}),
    })
  ),
  command_risk: section(
    z.object({
      blocked_patterns: z.array(z.string()).default([]),
    })
  ),
  file_policy: section(
    z.object({
      protected_paths: z.array(pathRuleSchema).default([
        { path: "**/.env", permissions: ["deny"], description: "Environment files often contain live secrets" },
        { path: "**/.env.*", permissions: ["deny"] },
        { path: "~/.ssh/**", permissions: ["deny"], description: "SSH private keys and known_hosts" },
        { path: "~/.aws/**", permissions: ["deny"], description: "AWS credential store" },
        { path: "~/.gnupg/**", permissions: ["deny"], description: "GPG keyring" },
        { path: "**/id_rsa*", permissions: ["deny"] },
        { path: "**/*.pem", permissions: ["deny"], description: "Certificate / key material" },
        { path: "**/credentials.json", permissions: ["deny"] },
        { path: "**/.git/**", permissions: ["deny"], description: "Git internals — history may hold secrets" },
        { path: "/etc/**", permissions: ["readonly"], description: "System configuration" },
        { path: "/proc/**", permissions: ["deny"], description: "Kernel / process introspection" },
        { path: "/dev/**", permissions: ["deny"], description: "Device nodes" },
      ]),
      max_bulk_delete: z.number().int().min(1).default(10),
      workspace_root: z.string().optional(),
      allow_outside_workspace: z.boolean().default(false),
    })
  ),
  url_policy: section(
    z.object({
      allowed_schemes: z.array(z.string()).default(["https"]),
      allowed_domains: z.array(z.string()).default([]),
      denied_domains: z.array(z.string()).default([]),
      block_private_networks: z.boolean().default(true),
    })
  ),
  secrets: section(
    z.object({
      enabled: z.boolean().default(true),
      scan_entropy: z.boolean().default(true),
      custom_patterns: z.array(secretPatternSchema).default([]),
    })
  ),
  injection: section(
    z.object({
      enabled: z.boolean().default(true),
      hits_for_high: z.number().int().min(1).default(2),
    })
  ),
  audit: section(
    z.object({
      enabled: z.boolean().default(true),
      log_dir: z.string().default(".actionwall/audit"),
      redact_secrets: z.boolean().default(true),
      log_allowed: z.boolean().default(true),
    })
  ),
});

export class PolicyValidationError extends Error {
  constructor(
    public readonly source: string,
    issues: z.ZodIssue[]
  ) {
    const lines = issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`);
    super(`Invalid policy document "${source}":\n${lines.join("\n")}`);
    this.name = "PolicyValidationError";
  }
}

/**
 * Load and validate a policy file (YAML or JSON). With no argument, returns
 * the built-in default policy.
 */
export function loadPolicy(path?: string): PolicyDoc {
  if (!path) return policySchema.parse({}) as PolicyDoc;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`Cannot read policy file "${path}": ${(err as Error).message}`);
  }
  let data: unknown;
  try {
    data = path.endsWith(".json") ? JSON.parse(raw) : parseYaml(raw);
  } catch (err) {
    throw new Error(`Cannot parse policy file "${path}": ${(err as Error).message}`);
  }
  if (data == null) data = {};
  const result = policySchema.safeParse(data);
  if (!result.success) throw new PolicyValidationError(path, result.error.issues);
  return result.data as PolicyDoc;
}

/** The built-in default policy (identical to policies/default.yaml). */
export function defaultPolicy(): PolicyDoc {
  return policySchema.parse({}) as PolicyDoc;
}

/** Helper for threshold checks in tests/tools. */
export function severityIn(list: RiskLevel[], level: RiskLevel): boolean {
  return list.includes(level);
}

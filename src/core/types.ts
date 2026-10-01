/**
 * Core data model shared by every scanner, the engine, the audit log and the CLI.
 */

/** Severity ladder. Higher wins when findings are aggregated. */
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export const RISK_ORDER: Record<RiskLevel, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export const RISK_ICONS: Record<RiskLevel, string> = {
  LOW: "🟢",
  MEDIUM: "🟡",
  HIGH: "🟠",
  CRITICAL: "🔴",
};

/** What the agent wants to do. This is the unit ActionWall inspects. */
export interface Action {
  /** Unique id for this action (uuid or any opaque string). */
  id: string;
  /** ISO-8601 timestamp of when the action was requested. */
  timestamp: string;
  /** Which agent is asking (used for per-agent tool policies). */
  agentId: string;
  /** Optional grouping id so an agent session can be reconstructed from the log. */
  sessionId?: string;
  /**
   * Canonical tool name. Built-ins the scanners understand:
   *   "shell"         — params.command
   *   "file.read" / "file.write" / "file.delete" / "file.list" — params.path
   *   "http.request" / "web.fetch" / "browser.open" / "web.search" — params.url
   * Any other tool name is allowed through the generic scanners unchanged.
   */
  tool: string;
  /** Tool arguments as a free-form object. */
  params: Record<string, unknown>;
  /**
   * Surrounding conversation material. `toolOutput` is the result the agent just
   * received from an external source (web page, file, tool response) — a classic
   * prompt-injection carrier. `userPrompt` is what the human asked for.
   */
  context?: ActionContext;
}

export interface ActionContext {
  userPrompt?: string;
  toolOutput?: string;
}

/** One violation (or noteworthy observation) produced by a scanner. */
export interface Finding {
  /** Scanner that produced the finding, e.g. "commandRisk". */
  scanner: string;
  /** Stable rule id, e.g. "CMD-RM-RECURSIVE-FORCE". */
  ruleId: string;
  severity: RiskLevel;
  /** Short headline, e.g. "Destructive filesystem operation". */
  title: string;
  /** Full human-readable explanation for the report. */
  reason: string;
  /** Which policy knob produced this rule, e.g. "file_policy.max_bulk_delete". */
  policyRef?: string;
  /** Snippet of the offending input — always passed through redaction. */
  evidence?: string;
}

export type Verdict = "ALLOW" | "BLOCK" | "ASK_HUMAN";

/** The engine's final answer for one action. */
export interface Decision {
  actionId: string;
  agentId: string;
  tool: string;
  verdict: Verdict;
  /** Highest severity among findings, or LOW when the action is clean. */
  risk: RiskLevel;
  findings: Finding[];
  /** One-line headline shown at the top of a report. */
  summary: string;
  /** Wall-clock cost of the scan in milliseconds. */
  latencyMs: number;
  timestamp: string;
}

/** Contract every scanner implements. Scanners are pure: no I/O side effects
 * beyond read-only filesystem counting performed by the file scanners. */
export interface Scanner {
  name: string;
  /** Return findings for the action; empty array when nothing is wrong / not applicable. */
  scan(action: Action, policy: PolicyDoc): Finding[];
}

/* ------------------------------------------------------------------ */
/* Policy document types (validated by core/policy.ts with zod).       */
/* ------------------------------------------------------------------ */

export type PathPermission = "deny" | "readonly" | "allow";

export interface ProtectedPath {
  path: string;
  permissions: PathPermission[];
  description?: string;
}

export interface PolicyDoc {
  version: 1;
  name: string;
  description?: string;
  /** If true, an internal scanner error blocks the action. Default true. */
  fail_closed: boolean;
  risk_thresholds: {
    /** Findings at these severities produce BLOCK. */
    block: RiskLevel[];
    /** Findings at these severities produce ASK_HUMAN. */
    ask: RiskLevel[];
  };
  tools: {
    default: "allow" | "deny";
    allow: string[];
    deny: string[];
    /** Per-agent overrides keyed by agentId. */
    agents: Record<string, { default?: "allow" | "deny"; allow: string[]; deny: string[] }>;
  };
  command_risk: {
    /** Extra regexes (string form) that should block shell commands. */
    blocked_patterns: string[];
  };
  file_policy: {
    protected_paths: ProtectedPath[];
    /** Maximum number of files a single delete action may remove. */
    max_bulk_delete: number;
    /** Root used for "outside workspace" checks. Defaults to process.cwd(). */
    workspace_root?: string;
    allow_outside_workspace: boolean;
  };
  url_policy: {
    allowed_schemes: string[];
    /** Empty list = any public domain is allowed. */
    allowed_domains: string[];
    denied_domains: string[];
    block_private_networks: boolean;
  };
  secrets: {
    enabled: boolean;
    scan_entropy: boolean;
    custom_patterns: { name: string; regex: string; severity: RiskLevel }[];
  };
  injection: {
    enabled: boolean;
    /** Distinct patterns that must hit before severity escalates to HIGH. */
    hits_for_high: number;
  };
  audit: {
    enabled: boolean;
    log_dir: string;
    redact_secrets: boolean;
    log_allowed: boolean;
  };
}

export function maxSeverity(findings: Finding[]): RiskLevel {
  let worst: RiskLevel = "LOW";
  for (const f of findings) {
    if (RISK_ORDER[f.severity] > RISK_ORDER[worst]) worst = f.severity;
  }
  return worst;
}

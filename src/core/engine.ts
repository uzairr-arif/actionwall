/**
 * ShieldEngine — the firewall itself.
 *
 * Pipeline for one action:
 *   1. run every scanner (order: tool permissions → command risk → file
 *      policy → secrets → URL policy → injection) and collect findings
 *   2. aggregate severity (worst finding wins)
 *   3. map severity → verdict via the policy's risk_thresholds
 *   4. write the decision to the tamper-evident audit log
 *
 * Failure semantics: a scanner that throws produces a synthetic finding.
 * With fail_closed (default) that finding is CRITICAL — a broken firewall
 * blocks instead of waving everything through.
 */

import { randomUUID } from "node:crypto";
import type { Action, Decision, Finding, RiskLevel, Scanner, Verdict } from "./types.js";
import type { PolicyDoc } from "./types.js";
import { AuditLogger } from "./audit.js";
import { toolPermissionsScanner } from "../scanners/toolPermissions.js";
import { commandRiskScanner } from "../scanners/commandRisk.js";
import { filePolicyScanner } from "../scanners/filePolicy.js";
import { secretsScanner } from "../scanners/secrets.js";
import { urlPolicyScanner } from "../scanners/urlPolicy.js";
import { injectionScanner } from "../scanners/injection.js";
import { maxSeverity } from "./types.js";

export const DEFAULT_SCANNERS: Scanner[] = [
  toolPermissionsScanner,
  commandRiskScanner,
  filePolicyScanner,
  secretsScanner,
  urlPolicyScanner,
  injectionScanner,
];

export class ActionBlockedError extends Error {
  constructor(public readonly decision: Decision) {
    super(`ActionWall ${decision.verdict}: ${decision.summary}`);
    this.name = "ActionBlockedError";
  }
}

export interface ShieldEngineOptions {
  /** Pass `false` to disable audit logging entirely. */
  audit?: AuditLogger | false;
  /** Replace or extend the scanner set. */
  scanners?: Scanner[];
}

export class ShieldEngine {
  readonly policy: PolicyDoc;
  readonly audit?: AuditLogger;
  private readonly scanners: Scanner[];

  constructor(policy: PolicyDoc, options: ShieldEngineOptions = {}) {
    this.policy = policy;
    this.scanners = options.scanners ?? DEFAULT_SCANNERS;
    if (policy.audit.enabled && options.audit !== false) {
      this.audit =
        options.audit ??
        new AuditLogger({ logDir: policy.audit.log_dir, redactSecrets: policy.audit.redact_secrets });
    }
  }

  /** Inspect an action and return the decision. Never throws for policy reasons. */
  check(action: Action): Decision {
    const started = performance.now();
    const timestamp = new Date().toISOString();
    const findings: Finding[] = [];

    for (const scanner of this.scanners) {
      try {
        findings.push(...scanner.scan(action, this.policy));
      } catch (err) {
        findings.push({
          scanner: scanner.name,
          ruleId: "SCANNER-FAILURE",
          severity: this.policy.fail_closed ? "CRITICAL" : "LOW",
          title: this.policy.fail_closed ? "Scanner failure (fail-closed)" : "Scanner failure (fail-open)",
          reason: `Scanner "${scanner.name}" threw an error and the policy is fail_${this.policy.fail_closed ? "closed" : "open"}: ${(err as Error).message}`,
        });
      }
    }

    const risk = maxSeverity(findings);
    const verdict = this.verdictFor(risk);
    const decision: Decision = {
      actionId: action.id,
      agentId: action.agentId,
      tool: action.tool,
      verdict,
      risk,
      findings,
      summary: headline(findings, verdict),
      latencyMs: Math.round((performance.now() - started) * 100) / 100,
      timestamp,
    };

    if (this.audit && (verdict !== "ALLOW" || this.policy.audit.log_allowed)) {
      try {
        this.audit.append(decision, action);
      } catch (err) {
        // Audit failures must not lose the decision itself.
        decision.findings.push({
          scanner: "audit",
          ruleId: "AUDIT-WRITE-FAILURE",
          severity: this.policy.fail_closed ? "CRITICAL" : "LOW",
          title: "Audit log write failed",
          reason: `Failed to append to the audit log: ${(err as Error).message}`,
        });
      }
    }
    return decision;
  }

  /** `check` + throw ActionBlockedError on BLOCK — the integration shape for agents. */
  guard(action: Action): Decision {
    const decision = this.check(action);
    if (decision.verdict === "BLOCK") throw new ActionBlockedError(decision);
    return decision;
  }

  private verdictFor(risk: RiskLevel): Verdict {
    if (this.policy.risk_thresholds.block.includes(risk)) return "BLOCK";
    if (this.policy.risk_thresholds.ask.includes(risk)) return "ASK_HUMAN";
    return "ALLOW";
  }
}

function headline(findings: Finding[], verdict: Verdict): string {
  if (findings.length === 0) return "No policy violations detected";
  const order: RiskLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  for (const level of order) {
    const worst = findings.find((f) => f.severity === level);
    if (worst) return worst.title;
  }
  return verdict === "ALLOW" ? "Allowed with warnings" : "Policy violation";
}

/** Convenience: build an Action with sane defaults (used by CLI and demos). */
export function makeAction(input: {
  tool: string;
  params: Record<string, unknown>;
  agentId?: string;
  sessionId?: string;
  context?: Action["context"];
  id?: string;
}): Action {
  return {
    id: input.id ?? randomUUID(),
    timestamp: new Date().toISOString(),
    agentId: input.agentId ?? "default-agent",
    sessionId: input.sessionId,
    tool: input.tool,
    params: input.params,
    context: input.context,
  };
}

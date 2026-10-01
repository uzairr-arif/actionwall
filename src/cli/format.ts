/**
 * Human-facing rendering of decisions — the colored report style shown in the
 * README. All functions return string arrays; callers decide how to print.
 */

import { bold, cyan, dim, green, red, yellow } from "../util/ansi.js";
import { RISK_ICONS, type Decision, type Verdict } from "../core/types.js";
import type { DemoStep } from "../demo/mockAgent.js";

const VERDICT_LABEL: Record<Verdict, string> = {
  ALLOW: "ALLOWED",
  ASK_HUMAN: "ASK HUMAN",
  BLOCK: "BLOCKED",
};

const VERDICT_COLOR: Record<Verdict, (t: string) => string> = {
  ALLOW: green,
  ASK_HUMAN: yellow,
  BLOCK: red,
};

function paramPreview(params: Record<string, unknown>, max = 90): string {
  let s = JSON.stringify(params);
  if (s.length > max) s = `${s.slice(0, max - 1)}…`;
  return s;
}

/** Full report for `actionwall check`. */
export function formatDecision(decision: Decision, logDir?: string): string[] {
  const color = VERDICT_COLOR[decision.verdict];
  const icon = decision.verdict === "BLOCK" ? "🔴" : decision.verdict === "ASK_HUMAN" ? "🟠" : "🟢";
  const lines: string[] = [];

  lines.push(color(bold(`${icon} ${VERDICT_LABEL[decision.verdict]} — ${decision.summary}`)));
  lines.push(dim(`   Tool: ${decision.tool} · Agent: ${decision.agentId} · Risk: ${decision.risk} · ${decision.latencyMs}ms`));

  if (decision.findings.length > 0) {
    lines.push(`   ${bold("Findings:")}`);
    for (const f of decision.findings) {
      lines.push(`   ${RISK_ICONS[f.severity]} ${bold(`[${f.ruleId}]`)} ${f.title} ${dim(`(${f.scanner})`)}`);
      lines.push(`     ${f.reason}`);
      if (f.policyRef) lines.push(dim(`     policy: ${f.policyRef}`));
      if (f.evidence) lines.push(dim(`     evidence: ${f.evidence}`));
    }
  }

  if (logDir) {
    const day = decision.timestamp.slice(0, 10);
    lines.push(dim(`   Audit: ${logDir}/audit-${day}.jsonl`));
  }
  return lines;
}

/** One demo step: header, action preview, verdict, top findings. */
export function formatStep(index: number, total: number, step: DemoStep, decision: Decision): string[] {
  const lines: string[] = [];
  const color = VERDICT_COLOR[decision.verdict];
  const icon = decision.verdict === "BLOCK" ? "🔴" : decision.verdict === "ASK_HUMAN" ? "🟠" : "🟢";

  lines.push("");
  lines.push(bold(cyan(`▸ Step ${index}/${total}`)) + ` ${step.label}`);
  lines.push(dim(`  ${decision.tool} ${paramPreview(step.action.params)}`));
  lines.push(
    color(`  ${icon} ${VERDICT_LABEL[decision.verdict]}`) +
      dim(`  risk=${decision.risk} · ${decision.latencyMs}ms · ${decision.summary}`)
  );
  for (const f of decision.findings.slice(0, 3)) {
    lines.push(`    ${RISK_ICONS[f.severity]} ${bold(`[${f.ruleId}]`)} ${f.reason}`);
  }
  if (decision.findings.length > 3) {
    lines.push(dim(`    … and ${decision.findings.length - 3} more finding(s)`));
  }
  return lines;
}

/** Pretty-print an audit entry (for `actionwall log`). */
export function formatAuditEntry(entry: {
  seq: number;
  timestamp: string;
  hash: string;
  decision: { verdict: Verdict; risk: string; summary: string };
  action: { agentId: string; tool: string; params: string };
}): string[] {
  const color = VERDICT_COLOR[entry.decision.verdict];
  const icon = entry.decision.verdict === "BLOCK" ? "🔴" : entry.decision.verdict === "ASK_HUMAN" ? "🟠" : "🟢";
  return [
    `${color(icon)} #${String(entry.seq).padStart(3, "0")} ${color(entry.decision.verdict.padEnd(9))} ${dim(entry.timestamp)} ${entry.decision.risk.padEnd(8)} ${entry.action.tool} ${dim(entry.action.agentId)}`,
    `     ${entry.decision.summary} ${dim(`hash ${entry.hash.slice(0, 12)}…`)}`,
  ];
}

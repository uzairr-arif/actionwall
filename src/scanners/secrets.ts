/**
 * Secret scanner: catches credentials leaving the agent's context through
 * tool arguments — an Authorization header pointing at a third-party host,
 * `curl` with an API key in the URL, a `db.connect(password=…)` call, etc.
 *
 * Detection: built-in signatures for well-known token formats + a
 * high-entropy-token heuristic for unknown formats + user-supplied regexes.
 * Everything the scanner reports is redacted before it reaches findings,
 * findings-as-strings, or the audit log.
 */

import type { Action, Finding, PolicyDoc, RiskLevel, Scanner } from "../core/types.js";
import { BUILTIN_SECRET_PATTERNS, isPlaceholderValue } from "../util/secretPatterns.js";
import { shannonEntropy } from "../util/entropy.js";
import { truncate } from "../util/secretPatterns.js";

const ENTROPY_TOKEN_RE = /[A-Za-z0-9_-]{32,}/g;
const ENTROPY_THRESHOLD = 4.0;
const MAX_FINDINGS = 12;

interface Span {
  start: number;
  end: number;
}

function overlaps(spans: Span[], start: number, end: number): boolean {
  return spans.some((s) => start < s.end && end > s.start);
}

export const secretsScanner: Scanner = {
  name: "secrets",

  scan(action: Action, policy: PolicyDoc): Finding[] {
    if (!policy.secrets.enabled) return [];

    const text = JSON.stringify(action.params);
    if (text.length === 0 || text === "{}") return [];

    const findings: Finding[] = [];
    const spans: Span[] = [];
    const redactEvidence = (s: string) => {
      const keep = Math.min(4, Math.floor(s.length / 4));
      return truncate(`${s.slice(0, keep)}*REDACTED*`, 60);
    };
    const add = (ruleId: string, severity: RiskLevel, name: string, matched: string, span: Span, extra?: string) => {
      if (findings.length >= MAX_FINDINGS) return;
      spans.push(span);
      findings.push({
        scanner: this.name,
        ruleId,
        severity,
        title: `Possible ${name} exposed in tool arguments`,
        reason: `A value matching the ${name} format was found in the action parameters${extra ? ` (${extra})` : ""}. Sending it through a tool call can leak it to third parties; the audit log stores only a redacted form.`,
        policyRef: "secrets.custom_patterns",
        evidence: redactEvidence(matched),
      });
    };

    const patterns = [
      ...BUILTIN_SECRET_PATTERNS.map((p) => ({ name: p.name, regex: p.regex, severity: p.severity, builtin: true })),
      ...policy.secrets.custom_patterns.map((p) => ({
        name: p.name,
        regex: new RegExp(p.regex, "g"),
        severity: p.severity as RiskLevel,
        builtin: false,
      })),
    ];

    for (const pattern of patterns) {
      const re = new RegExp(pattern.regex.source, pattern.regex.flags.includes("g") ? pattern.regex.flags : `${pattern.regex.flags}g`);
      let count = 0;
      for (const match of text.matchAll(re)) {
        if (count >= 5) break;
        const matched = match[0];
        if (matched === undefined) continue;
        count++;

        // The credential-assignment rule captures the value in group 1;
        // skip obvious placeholders like password=changeme or ${DB_PASS}.
        const value = match[1];
        if (pattern.name === "credential-assignment" && value !== undefined && isPlaceholderValue(value)) {
          continue;
        }
        add(
          `SEC-${pattern.name.toUpperCase()}`,
          pattern.severity,
          pattern.name,
          matched,
          { start: match.index ?? 0, end: (match.index ?? 0) + matched.length }
        );
      }
    }

    // High-entropy heuristic for unknown secret formats.
    if (policy.secrets.scan_entropy) {
      let count = 0;
      for (const match of text.matchAll(ENTROPY_TOKEN_RE)) {
        if (count >= 3) break;
        const token = match[0];
        const start = match.index ?? 0;
        if (token === undefined || overlaps(spans, start, start + token.length)) continue;
        if (shannonEntropy(token) >= ENTROPY_THRESHOLD) {
          count++;
          findings.push({
            scanner: this.name,
            ruleId: "SEC-HIGH-ENTROPY",
            severity: "MEDIUM",
            title: "Possible high-entropy credential",
            reason: `A ${token.length}-character high-entropy token was found in the action parameters. If it is not a credential, allow it via a scanner exception; if it is, remove it.`,
            evidence: redactEvidence(token),
          });
        }
      }
    }

    return findings;
  },
};

/**
 * Prompt-injection scanner.
 *
 * Inspects text flowing INTO the model — the tool output the agent just
 * received and the user prompt — for instructions trying to hijack the agent:
 * "ignore previous instructions", fake system markers, role-override lines,
 * exfiltration via markdown images, hidden/invisible characters.
 *
 * Honest scope (see docs/THREAT_MODEL.md): pattern heuristics catch the common
 * and lazy injections; paraphrased or multilingual attacks require an
 * LLM-based classifier, which ActionWall accepts as a pluggable scanner
 * rather than pretending regex is a complete defense.
 */

import type { Action, Finding, PolicyDoc, Scanner } from "../core/types.js";
import { truncate } from "../util/secretPatterns.js";

interface InjectionPattern {
  id: string;
  regex: RegExp;
  label: string;
}

const PATTERNS: InjectionPattern[] = [
  {
    id: "IGNORE-PRIOR",
    regex: /\bignore\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|past)\s+(?:instructions?|prompts?|rules?|directions?|context)\b/i,
    label: '"ignore previous instructions" override',
  },
  {
    id: "DISREGARD",
    regex: /\bdisregard\s+(?:all\s+|your\s+|any\s+|the\s+)?(?:instructions?|rules?|guardrails?|guidelines|constraints?|context)\b/i,
    label: '"disregard your rules" override',
  },
  {
    id: "ROLE-OVERRIDE",
    regex: /\byou\s+are\s+now\s+(?:a|an|the)\b/i,
    label: 'role override ("you are now a…")',
  },
  {
    id: "SYSTEM-PROMPT-EXTRACT",
    regex: /\b(?:reveal|repeat|print|show|output|dump|ignore)\s+(?:your\s+|the\s+|its\s+)?system\s+prompt\b/i,
    label: "system prompt extraction request",
  },
  {
    id: "FAKE-SYSTEM-MARKER",
    regex: /<\|im_start\|>|<\|endoftext\|>|\[SYSTEM\]|\{\{SYSTEM\}\}|(?:^|\n)\s*system\s*:\s*/im,
    label: "fake system/message marker",
  },
  {
    id: "NEW-INSTRUCTIONS",
    regex: /\bnew\s+(?:system\s+)?(?:instructions?|directives?|rules?|objective)\s*:/i,
    label: '"new instructions:" injection',
  },
  {
    id: "URGENT-EXEC",
    regex: /\b(?:important|urgent|emergency|critical)[^\n.]{0,60}\b(?:run|execute|delete|send|post|upload|exfiltrate)\b/i,
    label: 'urgent "do X now" directive',
  },
  {
    id: "IMPERSONATION",
    regex: /(?:^|\n)\s*(?:assistant|ai|agent|bot)\s*:\s*/im,
    label: "impersonated assistant turn",
  },
  {
    id: "EXFIL-IMAGE",
    regex: /!\[[^\]]*\]\(\s*(?:https?:)?\/\/[^)]*(?:[?&])(?:data|q|payload|token|d|secret|content)=[^)]*\)/i,
    label: "possible data exfiltration via markdown image URL",
  },
];

const HIDDEN_CHARS_RE = /[\u200B-\u200D\u2060\uFEFF]/;

export const injectionScanner: Scanner = {
  name: "injection",

  scan(action: Action, policy: PolicyDoc): Finding[] {
    if (!policy.injection.enabled) return [];

    const sources: { label: string; text?: string }[] = [
      { label: "tool output", text: action.context?.toolOutput },
      { label: "user prompt", text: action.context?.userPrompt },
    ];

    const findings: Finding[] = [];
    for (const source of sources) {
      const text = source.text;
      if (!text || text.length === 0) continue;

      const hits: { id: string; label: string; snippet: string }[] = [];
      for (const pattern of PATTERNS) {
        const m = pattern.regex.exec(text);
        if (m) {
          hits.push({ id: pattern.id, label: pattern.label, snippet: m[0] });
        }
      }
      let hidden = false;
      if (HIDDEN_CHARS_RE.test(text)) {
        hidden = true;
        hits.push({ id: "HIDDEN-CHARS", label: "hidden/invisible characters (zero-width or word-joiner)", snippet: "(invisible characters present)" });
      }
      if (hits.length === 0) continue;

      const exfil = hits.some((h) => h.id === "EXFIL-IMAGE");
      const distinct = new Set(hits.map((h) => h.id)).size;
      const severity = exfil || distinct >= policy.injection.hits_for_high ? "HIGH" : "MEDIUM";
      const labels = hits.slice(0, 3).map((h) => h.label).join("; ");

      findings.push({
        scanner: this.name,
        ruleId: exfil ? "INJ-EXFIL-IMAGE" : distinct >= policy.injection.hits_for_high ? "INJ-MULTI-PATTERN" : "INJ-SINGLE-PATTERN",
        severity,
        title: exfil ? "Possible data exfiltration via markdown image" : "Possible prompt injection",
        reason:
          `${severity === "HIGH" ? distinct : 1} injection pattern${distinct === 1 ? "" : "s"} detected in ${source.label}: ${labels}. ` +
          (exfil
            ? "A markdown image URL carries data out to a third-party server when the model renders it."
            : "Content inside tool output is untrusted input — an attacker-controlled page or file may be steering the agent."),
        policyRef: "injection.enabled",
        evidence: truncate(truncate(hits[0]!.snippet, 80)),
      });
    }
    return findings;
  },
};

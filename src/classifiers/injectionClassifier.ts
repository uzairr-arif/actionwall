/**
 * Pluggable injection classifier (v0.3).
 *
 * The interface lets you plug any scoring model into the engine: a local
 * classifier, an API call wrapped in a sync adapter, or the transparent
 * keyword baseline shipped below. Scores run from 0 (benign) to 1 (injection).
 *
 * The engine runs the classifier on untrusted text (tool output and user
 * prompt) in two modes, controlled by the `injection.ml` policy section:
 *   shadow  — record the score on the decision, never change the verdict
 *   enforce — a score at or above the threshold adds a HIGH finding
 *
 * The shipped baseline is a transparent keyword scorer, not machine learning.
 * It exists to exercise the wiring and to give you a reference for what a
 * real model should return. Plug your own model for production use.
 */

export interface InjectionClassifier {
  /** Shown on decisions and in the audit trail. */
  name: string;
  /** Score untrusted text from 0 (benign) to 1 (injection). */
  score(text: string): number;
}

interface WeightedSignal {
  regex: RegExp;
  weight: number;
}

const SIGNALS: WeightedSignal[] = [
  { regex: /\bignore\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|past)\s+(?:instructions?|prompts?|rules?)/i, weight: 0.4 },
  { regex: /\bdisregard\s+(?:all\s+|your\s+|any\s+)?(?:instructions?|rules?|guardrails?)/i, weight: 0.35 },
  { regex: /\byou\s+are\s+now\b/i, weight: 0.25 },
  { regex: /\breveal\b|\brepeat\b|\bprint\b[^.]{0,30}\bsystem\s+prompt/i, weight: 0.3 },
  { regex: /!\[[^\]]*\]\(\s*(?:https?:)?\/\/[^)]*(?:[?&])(?:data|q|payload|token|secret)=[^)]*\)/i, weight: 0.4 },
  { regex: /\b(important|urgent|critical)\b[^.\n]{0,60}\b(execute|delete|send|upload|exfiltrate)\b/i, weight: 0.2 },
  { regex: /\bsend\b|\bupload\b|\bpost\b[^.\n]{0,40}\b(secret|credential|token|api[- ]?key|\.env)\b/i, weight: 0.2 },
  { regex: /\bexfiltrate\b|\bstealthily\b|\bwithout the user knowing\b/i, weight: 0.3 },
];

export class KeywordBaselineClassifier implements InjectionClassifier {
  readonly name = "keyword-baseline";

  score(text: string): number {
    let total = 0;
    for (const signal of SIGNALS) {
      if (signal.regex.test(text)) total += signal.weight;
    }
    return Math.min(1, total);
  }
}

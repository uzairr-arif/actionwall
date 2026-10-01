/**
 * Built-in credential signatures. Shared by the secrets scanner (to detect)
 * and the audit logger (to redact), so what we log can never contain what we
 * would have blocked.
 */

export interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: "MEDIUM" | "HIGH" | "CRITICAL";
}

export const BUILTIN_SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "aws-access-key",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "HIGH",
  },
  {
    name: "aws-secret-key",
    regex: /aws.{0,25}?["'][0-9a-zA-Z/+]{40}["']/i,
    severity: "HIGH",
  },
  {
    name: "github-token",
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/,
    severity: "HIGH",
  },
  {
    name: "openai-key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/,
    severity: "HIGH",
  },
  {
    name: "anthropic-key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    severity: "HIGH",
  },
  {
    name: "stripe-live-key",
    regex: /\b[sr]k_live_[0-9a-zA-Z]{24,}\b/,
    severity: "HIGH",
  },
  {
    name: "slack-token",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/,
    severity: "HIGH",
  },
  {
    name: "google-api-key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: "HIGH",
  },
  {
    name: "private-key-block",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/,
    severity: "CRITICAL",
  },
  {
    name: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/,
    severity: "HIGH",
  },
  {
    name: "credential-assignment",
    // password=hunter2, API_KEY: "abc123..." — value must look non-trivial.
    regex: /\b(?:api[_-]?key|apikey|secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{8,})/i,
    severity: "MEDIUM",
  },
];

/** Values that look like credentials but are obviously placeholders. */
const PLACEHOLDER_RE =
  /^(?:\$\{.*\}|\$[A-Z_]+$|<[^>]+>|\*+$|x+$|\.+$|changeme|change-me|example.*|placeholder.*|your[-_].*|dummy.*|test.*|xxxx.*)$/i;

export function isPlaceholderValue(value: string): boolean {
  return PLACEHOLDER_RE.test(value.trim());
}

/**
 * Replace anything that looks like a credential with a redacted form that
 * keeps enough prefix for debugging ("AKIA…*REDACTED*").
 */
export function redactText(text: string): string {
  let out = text;
  for (const { regex } of BUILTIN_SECRET_PATTERNS) {
    out = out.replace(regex, (match, group1) => {
      // For credential-assignment the secret is in group 1; keep the key name.
      if (group1 !== undefined && group1.length > 0) {
        const idx = match.lastIndexOf(group1);
        const head = match.slice(0, idx);
        return `${head}*REDACTED*`;
      }
      const keep = Math.min(4, Math.floor(match.length / 4));
      return `${match.slice(0, keep)}*REDACTED*`;
    });
  }
  return out;
}

/** Truncate long evidence strings for reports. */
export function truncate(text: string, max = 120): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * Append-only JSONL audit log with a SHA-256 hash chain.
 *
 * Every record embeds the hash of the previous record, so deleting or editing
 * an entry after the fact breaks the chain and is caught by `verify()`.
 * This gives agents (and their humans) a tamper-evident record of everything
 * the firewall allowed or blocked.
 *
 * Records are written synchronously with appendFileSync. At firewall
 * latencies (<50ms per decision) the syscall cost is acceptable and durability
 * is worth more than throughput; batching is a listed roadmap item.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, appendFileSync, readdirSync } from "node:fs";
import * as path from "node:path";
import type { Action, Decision } from "./types.js";
import { redactText } from "../util/secretPatterns.js";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditEntry {
  seq: number;
  timestamp: string;
  prevHash: string;
  hash: string;
  decision: {
    verdict: Decision["verdict"];
    risk: Decision["risk"];
    summary: string;
    findings: Decision["findings"];
    latencyMs: number;
  };
  action: {
    id: string;
    agentId: string;
    tool: string;
    params: string; // JSON-stringified, secret-redacted
  };
}

export interface ChainVerification {
  file: string;
  entries: number;
  ok: boolean;
  /** Sequence number of the first broken link, when ok is false. */
  brokenAt?: number;
  reason?: string;
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export class AuditLogger {
  private readonly logDir: string;
  private readonly redactSecrets: boolean;
  /** Cache of {file → {prevHash, seq}} so appends don't re-read the file. */
  private readonly tips = new Map<string, { prevHash: string; seq: number }>();

  constructor(opts: { logDir: string; redactSecrets: boolean }) {
    this.logDir = opts.logDir;
    this.redactSecrets = opts.redactSecrets;
  }

  /** Today's log file: audit-YYYY-MM-DD.jsonl */
  fileFor(date = new Date()): string {
    const day = date.toISOString().slice(0, 10);
    return path.join(this.logDir, `audit-${day}.jsonl`);
  }

  listFiles(): string[] {
    if (!existsSync(this.logDir)) return [];
    return readdirSync(this.logDir)
      .filter((f) => f.endsWith(".jsonl"))
      .sort()
      .map((f) => path.join(this.logDir, f));
  }

  /** Append a decision (with its action) to today's log. Returns the entry written. */
  append(decision: Decision, action: Action): AuditEntry {
    const file = this.fileFor(new Date(decision.timestamp));
    mkdirSync(path.dirname(file), { recursive: true });

    const tip = this.tipFor(file);
    const seq = tip.seq + 1;
    const paramsJson = JSON.stringify(action.params, null, 0);

    const entry: AuditEntry = {
      seq,
      timestamp: decision.timestamp,
      prevHash: tip.prevHash,
      hash: "", // filled below; the chain covers the record body without `hash`
      decision: {
        verdict: decision.verdict,
        risk: decision.risk,
        summary: decision.summary,
        findings: decision.findings,
        latencyMs: decision.latencyMs,
      },
      action: {
        id: action.id,
        agentId: action.agentId,
        tool: action.tool,
        params: this.redactSecrets ? redactText(paramsJson) : paramsJson,
      },
    };
    entry.hash = sha256(entry.prevHash + JSON.stringify({ ...entry, hash: "" }));

    appendFileSync(file, JSON.stringify(entry) + "\n", "utf8");
    this.tips.set(file, { prevHash: entry.hash, seq });
    return entry;
  }

  /** Re-walk the whole chain of a log file and confirm every link. */
  verify(file: string = this.fileFor()): ChainVerification {
    if (!existsSync(file)) {
      return { file, entries: 0, ok: true, reason: "no log file yet" };
    }
    const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim().length > 0);
    let prevHash = GENESIS_HASH;
    for (let i = 0; i < lines.length; i++) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(lines[i]!) as AuditEntry;
      } catch (err) {
        return { file, entries: i, ok: false, brokenAt: i + 1, reason: `unparseable line ${(i + 1)}: ${(err as Error).message}` };
      }
      if (entry.prevHash !== prevHash) {
        return { file, entries: i, ok: false, brokenAt: entry.seq, reason: "prevHash does not match previous record" };
      }
      const expected = sha256(entry.prevHash + JSON.stringify({ ...entry, hash: "" }));
      if (entry.hash !== expected) {
        return { file, entries: i, ok: false, brokenAt: entry.seq, reason: "record hash mismatch — record was modified" };
      }
      prevHash = entry.hash;
    }
    return { file, entries: lines.length, ok: true };
  }

  /** Last `n` entries of a log file (default today's), oldest last. */
  tail(n: number, file: string = this.fileFor()): AuditEntry[] {
    if (!existsSync(file)) return [];
    const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim().length > 0);
    return lines.slice(-n).map((l) => JSON.parse(l) as AuditEntry);
  }

  private tipFor(file: string): { prevHash: string; seq: number } {
    const cached = this.tips.get(file);
    if (cached) return cached;
    let prevHash = GENESIS_HASH;
    let seq = 0;
    if (existsSync(file)) {
      const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.trim().length > 0);
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]!) as AuditEntry;
        prevHash = last.hash;
        seq = last.seq;
      }
    }
    const tip = { prevHash, seq };
    this.tips.set(file, tip);
    return tip;
  }
}

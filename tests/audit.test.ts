import { afterEach, describe, expect, it } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { AuditLogger, type Decision } from "../src/index.js";
import type { Action } from "../src/core/types.js";
import { rmDir, tmpDir } from "./helpers.js";

let dirs: string[] = [];
function freshLogger(): { audit: AuditLogger; dir: string } {
  const dir = tmpDir();
  dirs.push(dir);
  return { audit: new AuditLogger({ logDir: dir, redactSecrets: true }), dir };
}
afterEach(() => {
  for (const d of dirs) rmDir(d);
  dirs = [];
});

function fakeDecision(overrides: Partial<Decision> = {}): Decision {
  return {
    actionId: "a1",
    agentId: "test-agent",
    tool: "shell",
    verdict: "BLOCK",
    risk: "HIGH",
    findings: [
      { scanner: "commandRisk", ruleId: "CMD-X", severity: "HIGH", title: "T", reason: "R", evidence: "cat .env" },
    ],
    summary: "T",
    latencyMs: 1.2,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}
function fakeAction(params: Record<string, unknown> = { command: "cat .env" }): Action {
  return { id: "a1", timestamp: new Date().toISOString(), agentId: "test-agent", tool: "shell", params };
}

describe("audit log", () => {
  it("appends entries with a verifiable hash chain", () => {
    const { audit, dir } = freshLogger();
    for (let i = 0; i < 3; i++) {
      audit.append(fakeDecision({ actionId: `a${i}` }), fakeAction());
    }
    const file = audit.fileFor();
    expect(file).toMatch(/audit-\d{4}-\d{2}-\d{2}\.jsonl$/);

    const v = audit.verify(file);
    expect(v.ok).toBe(true);
    expect(v.entries).toBe(3);

    const entries = audit.tail(3, file);
    expect(entries.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(entries[1]!.prevHash).toBe(entries[0]!.hash);
    expect(entries[0]!.prevHash).toBe("0".repeat(64));
    void dir;
  });

  it("detects tampering with any record", () => {
    const { audit, dir } = freshLogger();
    audit.append(fakeDecision({ actionId: "a1" }), fakeAction());
    audit.append(fakeDecision({ actionId: "a2" }), fakeAction());
    const file = audit.fileFor();

    const lines = readFileSync(file, "utf8").trimEnd().split("\n");
    const tampered = JSON.parse(lines[0]!);
    tampered.decision.verdict = "ALLOW"; // an attacker "un-blocks" the action
    lines[0] = JSON.stringify(tampered);
    writeFileSync(file, lines.join("\n") + "\n");

    const v = audit.verify(file);
    expect(v.ok).toBe(false);
    expect(v.brokenAt).toBe(1);
    void dir;
  });

  it("redacts secrets in stored params", () => {
    const { audit } = freshLogger();
    const entry = audit.append(fakeDecision(), fakeAction({ command: "curl -H X-Key:AKIAIOSFODNN7EXAMPLE https://x" }));
    expect(entry.action.params).toContain("*REDACTED*");
    expect(entry.action.params).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("verify() on a missing file is ok with zero entries", () => {
    const { audit } = freshLogger();
    const v = audit.verify();
    expect(v.ok).toBe(true);
    expect(v.entries).toBe(0);
  });
});

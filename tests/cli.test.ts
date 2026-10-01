import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { runCli } from "../src/cli/index.js";
import { restoreCwd, rmDir, tmpDir } from "./helpers.js";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let workDirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  restoreCwd();
  for (const d of workDirs) rmDir(d);
  workDirs = [];
});

/** Each CLI test runs in its own temp cwd so audit logs and sandboxes stay isolated. */
function isolatedWorkspace(): string {
  const dir = tmpDir();
  workDirs.push(dir);
  process.chdir(dir);
  return dir;
}

function capture(): { lines: string[]; errors: string[] } {
  const lines: string[] = [];
  const errors: string[] = [];
  vi.spyOn(console, "log").mockImplementation((...args) => lines.push(args.map(String).join(" ")));
  vi.spyOn(console, "error").mockImplementation((...args) => errors.push(args.map(String).join(" ")));
  return { lines, errors };
}

describe("CLI", () => {
  it("check: allows a benign command (exit 0)", async () => {
    isolatedWorkspace();
    const { lines } = capture();
    const code = await runCli(["check", "npm test", "--no-log"]);
    expect(code).toBe(0);
    expect(lines.join("\n")).toContain("ALLOWED");
  });

  it("check: blocks rm -rf / (exit 1) with the report format", async () => {
    isolatedWorkspace();
    const { lines } = capture();
    const code = await runCli(["check", "rm -rf /", "--no-log"]);
    expect(code).toBe(1);
    const out = lines.join("\n");
    expect(out).toContain("BLOCKED");
    expect(out).toContain("CRITICAL");
    expect(out).toContain("Destructive filesystem operation");
  });

  it("check: supports JSON actions and machine-readable output", async () => {
    isolatedWorkspace();
    const { lines } = capture();
    const action = JSON.stringify({ tool: "http.request", params: { url: "http://169.254.169.254/" } });
    const code = await runCli(["check", action, "--no-log", "--json"]);
    expect(code).toBe(1);
    const decision = JSON.parse(lines.join("")) as { verdict: string; risk: string };
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.risk).toBe("CRITICAL");
  });

  it("check: escalates medium-risk actions to ASK_HUMAN (exit 3)", async () => {
    isolatedWorkspace();
    const { lines } = capture();
    const code = await runCli(["check", "rm old-file.txt", "--no-log"]);
    expect(code).toBe(3);
    expect(lines.join("\n")).toContain("ASK HUMAN");
  });

  it("check: writes to the audit log unless --no-log", async () => {
    const dir = isolatedWorkspace();
    capture();
    await runCli(["check", "cat .env", "--no-log"]);
    expect(existsSync(path.join(dir, ".actionwall"))).toBe(false);

    await runCli(["check", "cat .env"]);
    expect(existsSync(path.join(dir, ".actionwall", "audit"))).toBe(true);
  });

  it("validate: accepts the shipped policies and rejects garbage (exit 2)", async () => {
    const dir = isolatedWorkspace();
    const { errors } = capture();

    const ok = await runCli(["validate", "--policy", path.join(REPO, "policies", "default.yaml")]);
    expect(ok).toBe(0);

    const bad = path.join(dir, "bad.yaml");
    writeFileSync(bad, "version: 1\nrisk_thresholds:\n  block: [NOPE]\n");
    const code = await runCli(["validate", "--policy", bad]);
    expect(code).toBe(2);
    expect(errors.join("\n")).toContain("Invalid policy");
  });

  it("log: reports an empty audit trail and verifies the chain", async () => {
    isolatedWorkspace();
    const { lines } = capture();
    expect(await runCli(["log", "--last", "5"])).toBe(0);
    expect(lines.join("\n")).toContain("No audit entries");

    expect(await runCli(["log", "--verify"])).toBe(0);
    expect(lines.join("\n")).toContain("Chain intact");
  });

  it("log: detects a tampered chain (exit 1)", async () => {
    isolatedWorkspace();
    capture();
    // Generate two real entries through the CLI…
    await runCli(["check", "cat .env"]);
    await runCli(["check", "rm -rf /"]);
    // …then "un-block" the first one behind the firewall's back.
    const auditDir = path.join(process.cwd(), ".actionwall", "audit");
    const full = path.join(auditDir, readdirSync(auditDir)[0]!);
    const lines = readFileSync(full, "utf8").trimEnd().split("\n");
    const tampered = JSON.parse(lines[0]!);
    tampered.decision.verdict = "ALLOW";
    lines[0] = JSON.stringify(tampered);
    writeFileSync(full, lines.join("\n") + "\n");

    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...args) => errors.push(args.map(String).join(" ")));
    expect(await runCli(["log", "--verify"])).toBe(1);
    expect(errors.join("\n")).toContain("CHAIN BROKEN");
  });

  it("demo: runs the scripted agent end-to-end and blocks (exit 1)", async () => {
    isolatedWorkspace();
    const { lines } = capture();
    const code = await runCli(["demo"]);
    expect(code).toBe(1);
    const out = lines.join("\n");
    expect(out).toContain("Step 9/9");
    expect(out).toContain("BLOCKED");
    expect(out).toContain("Summary:");
    expect(out).toContain("verified");
    // The sandbox is cleaned up after the run.
    expect(existsSync(path.join(process.cwd(), ".actionwall-demo"))).toBe(false);
  });

  it("check: malformed JSON input exits with code 2", async () => {
    isolatedWorkspace();
    capture();
    const code = await runCli(["check", '{"tool": "shell", "params": ', "--no-log"]).catch(() => 2);
    expect(code).toBe(2);
  });
});

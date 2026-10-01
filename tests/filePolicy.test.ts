import { afterEach, describe, expect, it } from "vitest";
import { filePolicyScanner } from "../src/scanners/filePolicy.js";
import { makeFiles, restoreCwd, rmDir, shellAction, toolAction, tmpDir, defaultPolicy, type PolicyDoc } from "./helpers.js";

const policy = defaultPolicy();
let dirsToClean: string[] = [];

function workspace(): string {
  const dir = tmpDir();
  dirsToClean.push(dir);
  process.chdir(dir); // vitest "forks" pool isolates this per file
  return dir;
}

afterEach(() => {
  restoreCwd();
  for (const d of dirsToClean) rmDir(d);
  dirsToClean = [];
});

describe("filePolicy scanner", () => {
  it("allows reads and writes inside the workspace", () => {
    workspace();
    expect(filePolicyScanner.scan(toolAction("file.read", { path: "README.md" }), policy)).toEqual([]);
    expect(filePolicyScanner.scan(toolAction("file.write", { path: "src/out.txt", content: "x" }), policy)).toEqual([]);
    expect(filePolicyScanner.scan(shellAction("cat notes.txt"), policy)).toEqual([]);
  });

  it("blocks reads of .env via the default protected paths", () => {
    workspace();
    const findings = filePolicyScanner.scan(shellAction("cat .env"), policy);
    const hit = findings.find((f) => f.ruleId === "FP-PROTECTED-READ");
    expect(hit?.severity).toBe("HIGH");
    expect(hit?.policyRef).toContain("protected_paths");
  });

  it("blocks writes and deletes on protected paths, allows readonly access", () => {
    workspace();
    // /etc/** is readonly: reads pass, writes are blocked.
    expect(filePolicyScanner.scan(shellAction("cat /etc/passwd"), policy)).toEqual([]);
    const write = filePolicyScanner.scan(shellAction("echo x > /etc/hosts"), policy);
    expect(write.some((f) => f.ruleId === "FP-PROTECTED-WRITE" && f.severity === "HIGH")).toBe(true);

    const del = filePolicyScanner.scan(toolAction("file.delete", { path: "~/.ssh/id_rsa" }), policy);
    expect(del.some((f) => f.ruleId === "FP-PROTECTED-DELETE")).toBe(true);
  });

  it("blocks SSH key reads through the file tool", () => {
    workspace();
    const findings = filePolicyScanner.scan(toolAction("file.read", { path: "~/.ssh/id_rsa" }), policy);
    expect(findings.some((f) => f.ruleId === "FP-PROTECTED-READ")).toBe(true);
  });

  it("enforces workspace containment", () => {
    const ws = workspace();
    const outside = filePolicyScanner.scan(toolAction("file.write", { path: "../escape.txt" }), policy);
    expect(outside.some((f) => f.ruleId === "FP-OUTSIDE-WRITE" && f.severity === "HIGH")).toBe(true);

    const outsideRead = filePolicyScanner.scan(toolAction("file.read", { path: "../escape.txt" }), policy);
    expect(outsideRead.some((f) => f.ruleId === "FP-OUTSIDE-READ" && f.severity === "MEDIUM")).toBe(true);

    // Resolving ../ must not allow path traversal to sneak through.
    const traversal = filePolicyScanner.scan(shellAction(`cat ${JSON.stringify(ws + "/../../outside")}`), policy);
    expect(traversal.some((f) => f.ruleId === "FP-OUTSIDE-READ")).toBe(true);
  });

  it("respects allow_outside_workspace: true", () => {
    workspace();
    const permissive: PolicyDoc = {
      ...policy,
      file_policy: { ...policy.file_policy, allow_outside_workspace: true },
    };
    expect(filePolicyScanner.scan(toolAction("file.write", { path: "../escape.txt" }), permissive)).toEqual([]);
  });

  it("applies the bulk-delete limit to the file.delete tool", () => {
    const dir = tmpDir();
    dirsToClean.push(dir);
    workspace();
    makeFiles(dir, 12);
    const findings = filePolicyScanner.scan(toolAction("file.delete", { path: `${dir}/*` }), policy);
    const bulk = findings.find((f) => f.ruleId === "FP-BULK-DELETE");
    expect(bulk?.severity).toBe("CRITICAL");
    expect(bulk?.reason).toContain("12 files");
  });

  it("ignores actions with no file semantics", () => {
    workspace();
    expect(filePolicyScanner.scan(shellAction("echo hello"), policy)).toEqual([]);
    expect(filePolicyScanner.scan(toolAction("http.request", { url: "https://api.example.com" }), policy)).toEqual([]);
  });
});

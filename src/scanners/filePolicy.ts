/**
 * File-access policy scanner.
 *
 * Two layers, evaluated per (path, operation):
 *   1. protected_paths rules (first match wins): "deny" blocks everything,
 *      "readonly" permits reads only, "allow" permits everything.
 *   2. workspace containment: unless allow_outside_workspace is true, writes
 *      and deletes outside the workspace root are blocked and reads flagged.
 *
 * Understands both the file.* tool family and file-touching shell commands
 * (cat, rm, cp, redirects, …) so an agent cannot escape policy by changing
 * which tool it uses.
 */

import type { Action, Finding, PolicyDoc, Scanner } from "../core/types.js";
import { countDeletableFiles, normalizePath, pathMatches } from "../util/paths.js";
import { parseCommand, positionalArgs, redirectTargets, splitSegments } from "../util/shell.js";
import { redactText, truncate } from "../util/secretPatterns.js";

type Op = "read" | "write" | "delete";

const TOOL_OPS: Record<string, Op> = {
  "file.read": "read",
  "file.list": "read",
  "file.stat": "read",
  "file.search": "read",
  "file.write": "write",
  "file.edit": "write",
  "file.create": "write",
  "file.append": "write",
  "file.mkdir": "write",
  "file.delete": "delete",
  "file.rmdir": "delete",
};

const READ_CMDS = new Set(["cat", "head", "tail", "less", "more", "ls", "find", "stat", "grep", "rg", "wc", "file", "source", "diff", "du", "zip", "tar"]);
const WRITE_CMDS = new Set(["touch", "tee", "mkdir", "ln", "chmod", "chown", "install"]);
const DELETE_CMDS = new Set(["rmdir", "shred", "unlink", "truncate"]);

const PARAM_PATH_KEYS = ["path", "file", "filepath", "filename", "target", "source", "src", "destination", "dst", "dir"];
const NOT_A_PATH = /^(?:https?:\/\/|-|[\d.]+$|[A-Z_]+=)/;

interface FileOp {
  rawPath: string;
  op: Op;
}

function opAllowed(permissions: string[], op: Op): boolean {
  if (permissions.includes("allow")) return true;
  if (op === "read" && permissions.includes("readonly")) return true;
  return false;
}

/** Pull candidate file paths + their operation out of any action. */
function collectFileOps(action: Action): FileOp[] {
  const ops: FileOp[] = [];
  const addParam = (value: unknown, op: Op) => {
    if (typeof value === "string" && value.length > 0) ops.push({ rawPath: value, op });
    if (Array.isArray(value)) {
      for (const v of value) {
        if (typeof v === "string" && v.length > 0) ops.push({ rawPath: v, op });
      }
    }
  };

  // Tool-level paths.
  const toolOp = TOOL_OPS[action.tool];
  if (toolOp) {
    for (const key of PARAM_PATH_KEYS) addParam(action.params[key], toolOp);
  }

  // Shell-level paths.
  if (action.tool === "shell" && typeof action.params.command === "string") {
    const { segments } = splitSegments(action.params.command);
    for (const segment of segments) {
      const cmd = parseCommand(segment);
      if (!cmd) continue;
      const positional = positionalArgs(cmd.args).filter((a) => !NOT_A_PATH.test(a));
      if (cmd.name === "rm") {
        for (const p of positional) ops.push({ rawPath: p, op: "delete" });
      } else if (cmd.name === "cp" || cmd.name === "mv") {
        if (positional.length >= 2) {
          ops.push({ rawPath: positional[0]!, op: "read" });
          ops.push({ rawPath: positional[positional.length - 1]!, op: "write" });
        }
      } else if (READ_CMDS.has(cmd.name)) {
        for (const p of positional) ops.push({ rawPath: p, op: "read" });
      } else if (WRITE_CMDS.has(cmd.name)) {
        for (const p of positional) ops.push({ rawPath: p, op: "write" });
      } else if (DELETE_CMDS.has(cmd.name)) {
        for (const p of positional) ops.push({ rawPath: p, op: "delete" });
      }
      for (const target of redirectTargets(segment)) {
        if (!NOT_A_PATH.test(target)) ops.push({ rawPath: target, op: "write" });
      }
    }
  }
  return ops;
}

export const filePolicyScanner: Scanner = {
  name: "filePolicy",

  scan(action: Action, policy: PolicyDoc): Finding[] {
    const fileOps = collectFileOps(action);
    if (fileOps.length === 0) return [];

    const cwd = typeof action.params.cwd === "string" ? action.params.cwd : process.cwd();
    const workspaceRoot = normalizePath(policy.file_policy.workspace_root ?? cwd, cwd);
    const findings: Finding[] = [];
    const deletePaths: string[] = [];

    for (const { rawPath, op } of fileOps) {
      const norm = normalizePath(rawPath, cwd);
      if (op === "delete") deletePaths.push(norm);

      // Layer 1: explicit protected-path rules, first match wins.
      const ruleIndex = policy.file_policy.protected_paths.findIndex((rule) => pathMatches(rule.path, norm));
      if (ruleIndex !== -1) {
        const rule = policy.file_policy.protected_paths[ruleIndex]!;
        if (!opAllowed(rule.permissions, op)) {
          const opVerb = op === "read" ? "read" : op === "write" ? "modification of" : "deletion of";
          findings.push({
            scanner: this.name,
            ruleId: `FP-PROTECTED-${op.toUpperCase()}`,
            severity: "HIGH",
            title: "Protected path access",
            reason: `${opVerb.charAt(0).toUpperCase()}${opVerb.slice(1)} "${norm}" is blocked by protected_paths rule "${rule.path}"${rule.description ? ` (${rule.description})` : ""}.`,
            policyRef: `file_policy.protected_paths[${ruleIndex}]`,
            evidence: truncate(redactText(rawPath)),
          });
        }
        continue; // an explicit rule answers for this path entirely
      }

      // Layer 2: workspace containment.
      if (!policy.file_policy.allow_outside_workspace) {
        const inside = norm === workspaceRoot || norm.startsWith(`${workspaceRoot}/`);
        if (!inside) {
          findings.push({
            scanner: this.name,
            ruleId: op === "read" ? "FP-OUTSIDE-READ" : "FP-OUTSIDE-WRITE",
            severity: op === "read" ? "MEDIUM" : "HIGH",
            title: op === "read" ? "File access outside workspace" : "File modification outside workspace",
            reason: `"${norm}" is outside the workspace root "${workspaceRoot}" and allow_outside_workspace is false.`,
            policyRef: "file_policy.allow_outside_workspace",
            evidence: truncate(redactText(rawPath)),
          });
        }
      }
    }

    // Bulk-delete limit for the file.* tool family (shell `rm` is handled by
    // the commandRisk scanner).
    if (action.tool !== "shell" && deletePaths.length > 0) {
      const { files, capped } = countDeletableFiles(deletePaths, cwd);
      if (files > policy.file_policy.max_bulk_delete) {
        findings.push({
          scanner: this.name,
          ruleId: "FP-BULK-DELETE",
          severity: "CRITICAL",
          title: "Destructive filesystem operation",
          reason: `Delete would remove ${files}${capped ? "+" : ""} files; policy allows at most ${policy.file_policy.max_bulk_delete} (file_policy.max_bulk_delete).`,
          policyRef: "file_policy.max_bulk_delete",
        });
      }
    }

    return findings;
  },
};

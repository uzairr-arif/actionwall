#!/usr/bin/env node
/**
 * ActionWall CLI.
 *
 *   actionwall check   "rm -rf /project/*"     inspect an action before it runs
 *   actionwall validate --policy policies/default.yaml
 *   actionwall log     [--last N] [--verify]   read / verify the audit trail
 *   actionwall demo    [--policy path]         scripted agent protected live
 *
 * Exit codes: 0 allowed · 1 blocked · 3 needs human approval · 2 error
 */

import { Command } from "commander";
import { existsSync } from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { ShieldEngine, loadPolicy, makeAction, AuditLogger, type Action } from "../index.js";
import { formatDecision, formatAuditEntry } from "./format.js";
import { runDemo } from "../demo/mockAgent.js";
import { bold, dim, green, red } from "../util/ansi.js";

const VERSION = "0.1.0";

/** Policy resolution order: explicit flag > ./actionwall.yaml > ./policies/default.yaml > built-in. */
function resolvePolicyPath(explicit?: string): string | undefined {
  if (explicit) return explicit;
  return ["actionwall.yaml", "actionwall.yml", path.join("policies", "default.yaml")].find((c) => existsSync(c));
}

function buildAction(actionArg: string, opts: { tool: string; params?: string; context?: string; agent: string }): Action {
  const extraParams = opts.params ? (JSON.parse(opts.params) as Record<string, unknown>) : {};
  const context = opts.context ? JSON.parse(opts.context) : undefined;

  if (actionArg.trim().startsWith("{")) {
    // Full action JSON: {"tool": "...", "params": {...}, "context": {...}}
    const parsed = JSON.parse(actionArg) as Partial<Action>;
    return makeAction({
      tool: parsed.tool ?? opts.tool,
      params: (parsed.params as Record<string, unknown>) ?? extraParams,
      agentId: parsed.agentId ?? opts.agent,
      context: parsed.context ?? context,
    });
  }
  // Plain shell command.
  return makeAction({ tool: opts.tool, params: { ...extraParams, command: actionArg }, agentId: opts.agent, context });
}

export async function runCli(argv: string[]): Promise<number> {
  const program = new Command();
  let exitCode = 0;

  program
    .name("actionwall")
    .description("Security firewall for AI agents — every tool call, command and request is checked against policy before it runs.")
    .version(VERSION);

  program
    .command("check")
    .description("Check an action against the policy (a shell command, or a JSON action)")
    .argument("<action>", 'shell command, e.g. "rm -rf /tmp/*", or full JSON action {"tool":...,"params":{...}}')
    .option("-t, --tool <name>", "tool name when passing a plain command", "shell")
    .option("-p, --params <json>", "additional params as JSON")
    .option("-c, --context <json>", 'context JSON, e.g. {"toolOutput":"…"} to test prompt-injection detection')
    .option("-a, --agent <id>", "agent id", "cli-agent")
    .option("--policy <path>", "policy file (default: ./actionwall.yaml, ./policies/default.yaml, or built-in)")
    .option("--json", "emit the full Decision as JSON")
    .option("--no-log", "do not append this decision to the audit log")
    .action(async (actionArg: string, opts) => {
      const policy = loadPolicy(resolvePolicyPath(opts.policy));
      const engine = new ShieldEngine(policy, opts.log === false ? { audit: false } : {});
      const action = buildAction(actionArg, opts);
      const decision = engine.check(action);
      if (opts.json) {
        console.log(JSON.stringify(decision, null, 2));
      } else {
        for (const line of formatDecision(decision, policy.audit.enabled && opts.log !== false ? policy.audit.log_dir : undefined)) {
          console.log(line);
        }
      }
      exitCode = decision.verdict === "ALLOW" ? 0 : decision.verdict === "ASK_HUMAN" ? 3 : 1;
    });

  program
    .command("validate")
    .description("Validate a policy file")
    .option("--policy <path>", "policy file to validate (default resolution applies)")
    .action((opts) => {
      try {
        const resolved = resolvePolicyPath(opts.policy);
        const policy = loadPolicy(resolved);
        const source = resolved ?? "built-in defaults";
        console.log(green(`✓ Policy "${policy.name}" (${source}) is valid.`));
        console.log(
          dim(
            `  protected_paths: ${policy.file_policy.protected_paths.length} · max_bulk_delete: ${policy.file_policy.max_bulk_delete} · ` +
              `tools: ${policy.tools.default} · fail_closed: ${policy.fail_closed}`
          )
        );
      } catch (err) {
        console.error(red(`✗ ${(err as Error).message}`));
        exitCode = 2;
      }
    });

  program
    .command("log")
    .description("Show the tamper-evident audit log")
    .option("-n, --last <n>", "how many recent entries to show", "10")
    .option("--verify", "verify the SHA-256 hash chain instead of listing")
    .option("--dir <dir>", "audit log directory (default from policy)")
    .option("--policy <path>", "policy file for log_dir resolution")
    .option("--json", "emit entries as JSON")
    .action((opts) => {
      let logDir = opts.dir;
      if (!logDir) {
        const policy = loadPolicy(resolvePolicyPath(opts.policy));
        logDir = policy.audit.log_dir;
      }
      const audit = new AuditLogger({ logDir, redactSecrets: false });
      const file = audit.fileFor();

      if (opts.verify) {
        const v = audit.verify(file);
        if (v.ok) {
          console.log(green(`✓ Chain intact — ${v.entries} entries verified in ${file}`));
        } else {
          console.error(red(`✗ CHAIN BROKEN in ${file} at entry #${v.brokenAt}: ${v.reason}`));
          exitCode = 1;
        }
        return;
      }

      const entries = audit.tail(Number.parseInt(opts.last, 10) || 10, file);
      if (entries.length === 0) {
        console.log(dim(`No audit entries yet in ${file}. Run some agent actions first.`));
        return;
      }
      for (const entry of entries) {
        for (const line of formatAuditEntry(entry)) console.log(line);
      }
    });

  program
    .command("demo")
    .description("Run the scripted demo agent (9 actions, 3 allowed, 5 blocked, 1 escalated) behind the firewall")
    .option("--policy <path>", "policy file to run the demo with")
    .option("--keep-sandbox", "keep the .actionwall-demo/ sandbox after the run")
    .action(async (opts) => {
      console.log(bold("ActionWall demo — a mock coding agent behind the firewall"));
      console.log(dim("Every step is checked by the real engine with the real policy.\n"));
      const result = await runDemo({ policyPath: opts.policy, keepSandbox: opts.keepSandbox, print: (l) => console.log(l) });
      exitCode = result.blocked > 0 ? 1 : 0;
    });

  await program.parseAsync(argv, { from: "user" });
  return exitCode;
}

const isMainInvocation = process.argv[1] ? import.meta.url === pathToFileURL(process.argv[1]).href : false;
if (isMainInvocation) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      console.error(red(`Error: ${err instanceof Error ? err.message : String(err)}`));
      process.exitCode = 2;
    });
}

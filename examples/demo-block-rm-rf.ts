/**
 * The headline example from the README:
 *
 *   Agent wants to execute: rm -rf /project/*
 *
 *   ActionWall → 🔴 BLOCKED — Risk: CRITICAL
 *   Reason: Destructive filesystem operation
 *   Policy: not allowed to delete more than 10 files automatically
 *
 * We create a sandbox "project" with 12 files so the bulk-delete rule has
 * something real to count, then hand the command to the firewall.
 */

import { ShieldEngine, loadPolicy, makeAction } from "../src/index.js";
import { setupSandbox, cleanupSandbox } from "../src/demo/mockAgent.js";
import { formatDecision } from "../src/cli/format.js";

const projectDir = setupSandbox(); // .actionwall-demo/project with 12 files

try {
  const engine = new ShieldEngine(loadPolicy()); // built-in default policy

  const decision = engine.check(
    makeAction({
      tool: "shell",
      params: { command: `rm -rf ${JSON.stringify(projectDir)}/*` },
      agentId: "example-agent",
    })
  );

  for (const line of formatDecision(decision)) console.log(line);
  process.exitCode = decision.verdict === "ALLOW" ? 0 : 1;
} finally {
  cleanupSandbox();
}

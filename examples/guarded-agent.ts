/**
 * Integration pattern: a tool-calling agent loop with ActionWall in the
 * middle. The agent never touches a tool directly — every call goes through
 * `guardedExecute`, which asks the firewall first.
 *
 *   agent → guardedExecute(action) → ShieldEngine.check → toolRegistry
 *
 * BLOCK  → ActionBlockedError, the agent sees the decision and must adapt
 * ASK_HUMAN → in production, surface this to a human approver; here we deny
 * ALLOW → run the tool
 */

import { ShieldEngine, loadPolicy, makeAction, ActionBlockedError, type Action, type Decision } from "../src/index.js";

/** The agent's actual tool implementations. */
const toolRegistry: Record<string, (params: Record<string, unknown>) => string> = {
  "file.read": (p) => `contents of ${String(p.path)}: # Project …`,
  "file.list": (p) => `ls ${String(p.path)}: cache/, bundle.js`,
  "file.write": (p) => `wrote ${String(p.path)}`,
  "http.request": (p) => `GET ${String(p.url)} → 200 OK`,
  shell: (p) => `executed: ${String(p.command)}`,
};

const log: Decision[] = [];

function guardedExecute(engine: ShieldEngine, action: Action): string {
  const decision = engine.check(action);
  log.push(decision);

  if (decision.verdict === "BLOCK") {
    throw new ActionBlockedError(decision);
  }
  if (decision.verdict === "ASK_HUMAN") {
    // Production: enqueue for human approval and pause the agent.
    // Demo: deny and tell the agent why.
    return `⏸ needs human approval — ${decision.summary}. Ask the user for permission or choose a safer approach.`;
  }
  const tool = toolRegistry[action.tool];
  return tool ? tool(action.params) : `unknown tool ${action.tool}`;
}

// --- Simulated agent turn: "clean up build artifacts" -----------------------

const engine = new ShieldEngine(loadPolicy());

const agentPlan: { intent: string; action: Action }[] = [
  {
    intent: "check what is in the build directory",
    action: makeAction({ tool: "file.list", params: { path: "build" }, agentId: "guarded-demo" }),
  },
  {
    intent: "delete everything in the build directory",
    action: makeAction({ tool: "shell", params: { command: "rm -rf build/*" }, agentId: "guarded-demo" }),
  },
  {
    intent: "try to smuggle the deletion through an HTTP tool",
    action: makeAction({
      tool: "http.request",
      params: { url: "file:///etc/passwd" },
      agentId: "guarded-demo",
    }),
  },
];

for (const { intent, action } of agentPlan) {
  console.log(`\nAgent intent: ${intent}`);
  try {
    console.log(`  → ${guardedExecute(engine, action)}`);
  } catch (err) {
    if (err instanceof ActionBlockedError) {
      console.log(`  → ⛔ firewall: ${err.decision.verdict} (${err.decision.risk}) — ${err.decision.summary}`);
      for (const f of err.decision.findings.slice(0, 2)) {
        console.log(`      [${f.ruleId}] ${f.reason}`);
      }
    } else {
      throw err;
    }
  }
}

console.log(`\n${log.length} decisions logged to ${engine.audit?.fileFor() ?? "(audit disabled)"}`);

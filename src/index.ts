/**
 * ActionWall — security firewall for AI agents.
 *
 * Public API:
 *   ShieldEngine        — the firewall: check(action) → Decision, guard(action)
 *   loadPolicy          — load + validate a YAML/JSON policy file
 *   defaultPolicy       — built-in default policy
 *   AuditLogger         — tamper-evident JSONL audit log
 *   makeAction          — Action builder helper
 *   ActionBlockedError  — thrown by guard() on BLOCK
 *   DEFAULT_SCANNERS    — the six built-in scanners, in pipeline order
 *   Scanners are also exported individually for custom pipelines.
 */

export * from "./core/types.js";
export { ShieldEngine, ActionBlockedError, makeAction, DEFAULT_SCANNERS } from "./core/engine.js";
export type { ShieldEngineOptions } from "./core/engine.js";
export { loadPolicy, defaultPolicy, PolicyValidationError, policySchema, riskLevelSchema } from "./core/policy.js";
export { AuditLogger, GENESIS_HASH } from "./core/audit.js";
export type { AuditEntry, ChainVerification } from "./core/audit.js";
export { toolPermissionsScanner } from "./scanners/toolPermissions.js";
export { commandRiskScanner } from "./scanners/commandRisk.js";
export { filePolicyScanner } from "./scanners/filePolicy.js";
export { secretsScanner } from "./scanners/secrets.js";
export { urlPolicyScanner } from "./scanners/urlPolicy.js";
export { injectionScanner } from "./scanners/injection.js";
export { redactText } from "./util/secretPatterns.js";
export { runDemo, demoSteps, setupSandbox, cleanupSandbox } from "./demo/mockAgent.js";

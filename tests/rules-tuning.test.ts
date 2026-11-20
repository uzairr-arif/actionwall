import { describe, expect, it } from "vitest";
import { ShieldEngine } from "../src/index.js";
import { defaultPolicy } from "../src/core/policy.js";
import type { PolicyDoc } from "../src/core/types.js";
import { shellAction } from "./helpers.js";

function policyWith(rules: PolicyDoc["rules"]): PolicyDoc {
  const base = defaultPolicy();
  return { ...base, rules };
}

describe("rule tuning (v0.3)", () => {
  it("downgrades a severity, softening the verdict", () => {
    // chmod 777 is HIGH by default (BLOCK); downgraded to MEDIUM it escalates instead.
    const engine = new ShieldEngine(
      policyWith({ severities: { "CMD-WORLD-WRITABLE": "MEDIUM" }, exceptions: [] }),
      { audit: false }
    );
    const decision = engine.check(shellAction("chmod 777 shared-dir"));
    expect(decision.risk).toBe("MEDIUM");
    expect(decision.verdict).toBe("ASK_HUMAN");
    expect(decision.findings.find((f) => f.ruleId === "CMD-WORLD-WRITABLE")?.severity).toBe("MEDIUM");
  });

  it("upgrades a severity, hardening the verdict", () => {
    // A single rm is MEDIUM (ASK_HUMAN); upgraded to CRITICAL it blocks outright.
    const engine = new ShieldEngine(
      policyWith({ severities: { "CMD-RM": "CRITICAL" }, exceptions: [] }),
      { audit: false }
    );
    const decision = engine.check(shellAction("rm old-file.txt"));
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.risk).toBe("CRITICAL");
  });

  it("suppresses a protected-path read when the evidence matches an exception glob", () => {
    // The default policy denies **/*.pem; a build agent that may read certificates
    // excepts the rule for pem evidence.
    const engine = new ShieldEngine(
      policyWith({
        severities: {},
        exceptions: [{ ruleId: "FP-PROTECTED-READ", matches: "**/*.pem", reason: "build agents may read certificates" }],
      }),
      { audit: false }
    );
    const pem = engine.check({ ...shellAction("cat"), tool: "file.read", params: { path: "certs/server.pem" } });
    expect(pem.verdict).toBe("ALLOW");
    expect(pem.findings.find((f) => f.ruleId === "FP-PROTECTED-READ")).toBeUndefined();

    // The exception is evidence-scoped: other protected paths stay blocked.
    const env = engine.check({ ...shellAction("cat"), tool: "file.read", params: { path: ".env" } });
    expect(env.verdict).toBe("BLOCK");
  });

  it("suppresses a command rule for whitelisted command patterns", () => {
    const engine = new ShieldEngine(
      policyWith({
        severities: {},
        exceptions: [{ ruleId: "CMD-PRIVILEGE-ESCALATION", matches: "sudo systemctl restart *", reason: "ops runbook" }],
      }),
      { audit: false }
    );
    const allowed = engine.check(shellAction("sudo systemctl restart nginx"));
    expect(allowed.findings.find((f) => f.ruleId === "CMD-PRIVILEGE-ESCALATION")).toBeUndefined();

    const other = engine.check(shellAction("sudo rm -rf /var/log"));
    expect(other.findings.some((f) => f.ruleId === "CMD-PRIVILEGE-ESCALATION")).toBe(true);
  });

  it("cannot tune protected rules: scanner failures still block", () => {
    const broken = {
      name: "brokenScanner",
      scan: () => {
        throw new Error("boom");
      },
    };
    const engine = new ShieldEngine(
      policyWith({
        severities: { "SCANNER-FAILURE": "LOW" },
        exceptions: [{ ruleId: "SCANNER-FAILURE", matches: "*" }],
      }),
      { audit: false, scanners: [broken] }
    );
    const decision = engine.check(shellAction("ls"));
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.risk).toBe("CRITICAL");
  });

  it("leaves default policies untouched when no rules section is configured", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    expect(engine.check(shellAction("chmod 777 /etc/hosts")).verdict).toBe("BLOCK");
    expect(engine.check({ ...shellAction("cat"), tool: "file.read", params: { path: ".env" } }).verdict).toBe("BLOCK");
  });
});

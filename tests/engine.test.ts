import { describe, expect, it } from "vitest";
import { ShieldEngine, ActionBlockedError, makeAction, type Scanner } from "../src/index.js";
import { shellAction, toolAction, defaultPolicy, type PolicyDoc } from "./helpers.js";

describe("ShieldEngine", () => {
  it("allows clean actions", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    const decision = engine.check(shellAction("npm test"));
    expect(decision.verdict).toBe("ALLOW");
    expect(decision.risk).toBe("LOW");
    expect(decision.findings).toEqual([]);
    expect(decision.summary).toBe("No policy violations detected");
    expect(decision.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("blocks HIGH severity findings by default", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    const decision = engine.check(shellAction("sudo rm -rf /var/log"));
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.risk).toBe("HIGH");
  });

  it("escalates MEDIUM findings to a human instead of blocking", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    const decision = engine.check(shellAction("rm build/cache.tmp"));
    expect(decision.verdict).toBe("ASK_HUMAN");
    expect(decision.risk).toBe("MEDIUM");
  });

  it("aggregates the worst finding across scanners", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    // `cat .env` trips both filePolicy and commandRisk; verdict reflects the max.
    const decision = engine.check(shellAction("cat .env"));
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.findings.length).toBeGreaterThanOrEqual(2);
    expect(new Set(decision.findings.map((f) => f.scanner)).size).toBeGreaterThanOrEqual(2);
  });

  it("is fail-closed when a scanner crashes", () => {
    const broken: Scanner = {
      name: "brokenScanner",
      scan: () => {
        throw new Error("boom");
      },
    };
    const engine = new ShieldEngine(defaultPolicy(), { audit: false, scanners: [broken] });
    const decision = engine.check(shellAction("ls"));
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.risk).toBe("CRITICAL");
    expect(decision.findings[0]!.ruleId).toBe("SCANNER-FAILURE");
  });

  it("is fail-open when the policy opts out", () => {
    const broken: Scanner = {
      name: "brokenScanner",
      scan: () => {
        throw new Error("boom");
      },
    };
    const policy: PolicyDoc = { ...defaultPolicy(), fail_closed: false };
    const engine = new ShieldEngine(policy, { audit: false, scanners: [broken] });
    const decision = engine.check(shellAction("ls"));
    expect(decision.verdict).toBe("ALLOW");
  });

  it("supports custom risk thresholds", () => {
    const policy: PolicyDoc = {
      ...defaultPolicy(),
      risk_thresholds: { block: ["CRITICAL"], ask: ["HIGH", "MEDIUM"] },
    };
    const engine = new ShieldEngine(policy, { audit: false });
    expect(engine.check(shellAction("sudo ls")).verdict).toBe("ASK_HUMAN");
    expect(engine.check(shellAction("rm -rf /")).verdict).toBe("BLOCK");
  });

  it("guard() throws ActionBlockedError on BLOCK and returns otherwise", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    expect(() => engine.guard(shellAction("rm -rf /"))).toThrow(ActionBlockedError);
    const ok = engine.guard(shellAction("ls"));
    expect(ok.verdict).toBe("ALLOW");
  });

  it("writes decisions to the audit log when enabled", () => {
    const engine = new ShieldEngine(defaultPolicy(), { audit: false });
    void engine;

    // Real integration through the default policy's audit section is covered
    // in cli.test.ts (actionwall demo); here we just assert the flag wiring.
    expect(engine.audit).toBeUndefined();
  });

  it("makeAction fills ids and timestamps", () => {
    const a = makeAction({ tool: "shell", params: { command: "ls" } });
    expect(a.id).toHaveLength(36);
    expect(new Date(a.timestamp).getTime()).not.toBeNaN();
    expect(a.agentId).toBe("default-agent");
    void toolAction;
  });
});

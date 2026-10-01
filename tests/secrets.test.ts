import { describe, expect, it } from "vitest";
import { secretsScanner } from "../src/scanners/secrets.js";
import { toolAction, defaultPolicy } from "./helpers.js";

const policy = defaultPolicy();

describe("secrets scanner", () => {
  it("detects AWS access keys", () => {
    const findings = secretsScanner.scan(
      toolAction("http.request", { url: "https://api.example.com", headers: { "X-Key": "AKIAIOSFODNN7EXAMPLE" } }),
      policy
    );
    const hit = findings.find((f) => f.ruleId === "SEC-AWS-ACCESS-KEY");
    expect(hit?.severity).toBe("HIGH");
  });

  it("detects private key blocks as CRITICAL", () => {
    const findings = secretsScanner.scan(
      toolAction("file.write", { path: "out.pem", content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----" }),
      policy
    );
    expect(findings.some((f) => f.ruleId === "SEC-PRIVATE-KEY-BLOCK" && f.severity === "CRITICAL")).toBe(true);
  });

  it("detects GitHub and OpenAI token formats", () => {
    const gh = secretsScanner.scan(toolAction("shell", { command: "gh auth token ghp_abcdefghijklmnopqrstuvwxyz0123456789" }), policy);
    expect(gh.some((f) => f.ruleId === "SEC-GITHUB-TOKEN")).toBe(true);

    const oai = secretsScanner.scan(toolAction("http.request", { headers: { Authorization: "Bearer sk-proj-abcdefghij0123456789ABCDE" } }), policy);
    expect(oai.some((f) => f.ruleId === "SEC-OPENAI-KEY")).toBe(true);
  });

  it("detects credential assignments but skips placeholders", () => {
    const real = secretsScanner.scan(toolAction("db.connect", { params: { password: "hunter2secret99" } }), policy);
    expect(real.some((f) => f.ruleId === "SEC-CREDENTIAL-ASSIGNMENT")).toBe(true);

    const placeholder = secretsScanner.scan(
      toolAction("db.connect", { params: { password: "changeme", api_key: "${DB_API_KEY}" } }),
      policy
    );
    expect(placeholder).toEqual([]);
  });

  it("flags unknown high-entropy tokens at MEDIUM", () => {
    const findings = secretsScanner.scan(
      toolAction("http.request", { url: "https://x.example", headers: { "X-Client-Id": "Zx9Qk2Rm7Tw4Yb1Nv5Cd8Eg3Ju6Hs0Ai2Lo5Py7Xa" } }),
      policy
    );
    expect(findings.some((f) => f.ruleId === "SEC-HIGH-ENTROPY" && f.severity === "MEDIUM")).toBe(true);
  });

  it("never emits the raw secret in findings or evidence", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const findings = secretsScanner.scan(toolAction("http.request", { headers: { "X-Key": secret } }), policy);
    for (const f of findings) {
      expect(JSON.stringify(f)).not.toContain(secret);
    }
    expect(findings[0]!.evidence).toContain("*REDACTED*");
  });

  it("supports custom patterns from policy", () => {
    const custom = {
      ...policy,
      secrets: { ...policy.secrets, custom_patterns: [{ name: "jira-token", regex: "jira_[A-Za-z0-9]{16,}", severity: "HIGH" as const }] },
    };
    const findings = secretsScanner.scan(toolAction("http.request", { body: "token=jira_abcdefghijklmnop1234" }), custom);
    expect(findings.some((f) => f.ruleId === "SEC-JIRA-TOKEN")).toBe(true);
  });

  it("passes clean actions through", () => {
    expect(secretsScanner.scan(toolAction("http.request", { url: "https://api.example.com/repos" }), policy)).toEqual([]);
  });
});

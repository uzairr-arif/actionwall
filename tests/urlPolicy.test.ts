import { describe, expect, it } from "vitest";
import { urlPolicyScanner, domainMatches } from "../src/scanners/urlPolicy.js";
import { shellAction, toolAction, defaultPolicy } from "./helpers.js";

const policy = defaultPolicy();

describe("urlPolicy scanner", () => {
  it("blocks cloud metadata endpoints as CRITICAL (SSRF)", () => {
    const findings = urlPolicyScanner.scan(
      toolAction("http.request", { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }),
      policy
    );
    const meta = findings.find((f) => f.ruleId === "URL-METADATA");
    expect(meta?.severity).toBe("CRITICAL");
    expect(meta?.title).toContain("SSRF");
  });

  it("blocks private network targets", () => {
    for (const url of ["http://192.168.1.10/admin", "http://10.0.0.5:8080", "http://localhost:3000", "https://service.internal"]) {
      const findings = urlPolicyScanner.scan(toolAction("http.request", { url }), policy);
      expect(findings.some((f) => f.ruleId === "URL-PRIVATE-NETWORK"), url).toBe(true);
    }
  });

  it("allows normal HTTPS traffic when no allowlist is configured", () => {
    expect(urlPolicyScanner.scan(toolAction("http.request", { url: "https://api.github.com/repos" }), policy)).toEqual([]);
  });

  it("enforces scheme rules (file:// and plain http are rejected)", () => {
    const file = urlPolicyScanner.scan(toolAction("http.request", { url: "file:///etc/passwd" }), policy);
    expect(file.some((f) => f.ruleId === "URL-SCHEME")).toBe(true);

    const http = urlPolicyScanner.scan(toolAction("http.request", { url: "http://api.example.com/data" }), policy);
    expect(http.some((f) => f.ruleId === "URL-SCHEME")).toBe(true);
  });

  it("checks URLs embedded in shell commands and implicit curl hosts", () => {
    const findings = urlPolicyScanner.scan(shellAction("curl http://localhost:8080/admin"), policy);
    expect(findings.some((f) => f.ruleId === "URL-PRIVATE-NETWORK")).toBe(true);
  });

  it("supports domain allowlists and denylists with wildcards", () => {
    const allowlist = { ...policy, url_policy: { ...policy.url_policy, allowed_domains: ["api.github.com"] } };
    const blocked = urlPolicyScanner.scan(toolAction("http.request", { url: "https://evil.example.com/x" }), allowlist);
    expect(blocked.some((f) => f.ruleId === "URL-DOMAIN-NOT-ALLOWED")).toBe(true);
    expect(urlPolicyScanner.scan(toolAction("http.request", { url: "https://api.github.com/repos" }), allowlist)).toEqual([]);

    const denylist = { ...policy, url_policy: { ...policy.url_policy, denied_domains: ["*.evil.com"] } };
    const denied = urlPolicyScanner.scan(toolAction("http.request", { url: "https://sub.evil.com/x" }), denylist);
    expect(denied.some((f) => f.ruleId === "URL-DENIED-DOMAIN")).toBe(true);
  });

  it("matches wildcard domains precisely", () => {
    expect(domainMatches("a.b.example.com", "*.example.com")).toBe(true);
    expect(domainMatches("example.com", "*.example.com")).toBe(true);
    expect(domainMatches("notexample.com", "*.example.com")).toBe(false);
    expect(domainMatches("api.github.com", "api.github.com")).toBe(true);
  });
});

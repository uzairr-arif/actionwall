/**
 * URL / domain policy scanner with SSRF protection.
 *
 * Inspects outbound destinations from the web tool family (http.request,
 * web.fetch, browser.*, web.search) and from shell commands (curl, wget,
 * httpie). Checks, in order of severity:
 *   - cloud metadata endpoints (CRITICAL — the classic SSRF prize)
 *   - other private/loopback network targets (HIGH)
 *   - explicitly denied domains (HIGH)
 *   - domain allowlist violations when one is configured (HIGH)
 *   - disallowed URL schemes, e.g. file:// or implicit http (HIGH)
 */

import type { Action, Finding, PolicyDoc, Scanner } from "../core/types.js";
import { redactText, truncate } from "../util/secretPatterns.js";
import { splitSegments } from "../util/shell.js";

const WEB_TOOLS = new Set(["http.request", "http.get", "http.post", "web.fetch", "web.search", "browser.open", "browser.navigate"]);
const SHELL_FETCHERS = new Set(["curl", "wget", "http", "https", "httpie", "gh", "fetch"]);
const URL_RE = /\b(?:https?|ftp|file):\/\/[^\s'"<>\\)\]]+/g;

const METADATA_HOSTS = new Set(["169.254.169.254", "metadata.google.internal", "100.100.100.200"]);

/** hostname → is it a private/loopback/link-local target? */
function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".home.arpa")) {
    return true;
  }
  // IPv4
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }
  // IPv6 — loopback, link-local (fe80::/10), unique-local (fc00::/7)
  if (h === "::1" || h === "::") return true;
  if (h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb")) {
    return true;
  }
  return false;
}

/** "api.example.com" vs patterns like "example.com" or "*.example.com". */
export function domainMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return h === base || h.endsWith(`.${base}`);
  }
  return h === p;
}

interface ParsedUrl {
  raw: string;
  scheme: string;
  host: string;
}

/** Extract candidate URLs from an action's params. */
function extractUrls(action: Action): ParsedUrl[] {
  const urls: ParsedUrl[] = [];
  const consider = (candidate: string) => {
    const raw = candidate.trim();
    if (raw.length === 0) return;
    try {
      const u = new URL(raw.includes("://") ? raw : `http://${raw}`);
      urls.push({ raw, scheme: u.protocol.replace(/:$/, "").toLowerCase(), host: u.hostname });
    } catch {
      // Not a parseable URL — ignore.
    }
  };

  if (WEB_TOOLS.has(action.tool)) {
    for (const key of ["url", "uri", "host", "base_url", "baseUrl"]) {
      const v = action.params[key];
      if (typeof v === "string") consider(v);
    }
  }

  if (action.tool === "shell" && typeof action.params.command === "string") {
    for (const match of action.params.command.matchAll(URL_RE)) {
      consider(match[0]);
    }
    const { segments } = splitSegments(action.params.command);
    for (const seg of segments) {
      const words = seg.trim().split(/\s+/);
      if (words.length >= 2 && SHELL_FETCHERS.has(words[0]!)) {
        const arg = words.find((w, i) => i > 0 && !w.startsWith("-") && !w.includes("://"));
        if (arg) consider(arg);
      }
    }
  }

  // Any tool that carries a url-ish param is checked too.
  if (!WEB_TOOLS.has(action.tool)) {
    const v = action.params.url;
    if (typeof v === "string") consider(v);
  }

  return urls;
}

export const urlPolicyScanner: Scanner = {
  name: "urlPolicy",

  scan(action: Action, policy: PolicyDoc): Finding[] {
    const urls = extractUrls(action);
    if (urls.length === 0) return [];

    const cfg = policy.url_policy;
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const push = (f: Finding) => {
      const key = `${f.ruleId}:${f.evidence}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(f);
      }
    };

    for (const { raw, scheme, host } of urls) {
      const evidence = truncate(redactText(raw), 100);

      if (cfg.block_private_networks && METADATA_HOSTS.has(host.toLowerCase())) {
        push({
          scanner: this.name,
          ruleId: "URL-METADATA",
          severity: "CRITICAL",
          title: "Cloud metadata endpoint access (SSRF)",
          reason: `"${host}" is a cloud instance-metadata service. Prompt-injected agents historically steal IAM credentials here. Metadata endpoints are never a legitimate agent destination.`,
          evidence,
        });
      }

      if (cfg.block_private_networks && isPrivateHost(host)) {
        push({
          scanner: this.name,
          ruleId: "URL-PRIVATE-NETWORK",
          severity: "HIGH",
          title: "Private network access (SSRF)",
          reason: `"${host}" resolves into loopback/link-local/private address space. Outbound requests to private networks are a server-side request forgery vector.`,
          evidence,
        });
      }

      if (cfg.denied_domains.some((d) => domainMatches(host, d))) {
        push({
          scanner: this.name,
          ruleId: "URL-DENIED-DOMAIN",
          severity: "HIGH",
          title: "Denied domain",
          reason: `"${host}" is on the denied_domains list.`,
          policyRef: "url_policy.denied_domains",
          evidence,
        });
      } else if (cfg.allowed_domains.length > 0 && !cfg.allowed_domains.some((d) => domainMatches(host, d))) {
        push({
          scanner: this.name,
          ruleId: "URL-DOMAIN-NOT-ALLOWED",
          severity: "HIGH",
          title: "Domain not in allowlist",
          reason: `"${host}" is not on allowed_domains and an allowlist is configured.`,
          policyRef: "url_policy.allowed_domains",
          evidence,
        });
      }

      if (!cfg.allowed_schemes.includes(scheme)) {
        push({
          scanner: this.name,
          ruleId: "URL-SCHEME",
          severity: "HIGH",
          title: "Disallowed URL scheme",
          reason: `Scheme "${scheme}:" is not in allowed_schemes [${cfg.allowed_schemes.join(", ")}]. Non-HTTPS schemes can carry local files (file://) or unencrypted traffic.`,
          policyRef: "url_policy.allowed_schemes",
          evidence,
        });
      }
    }

    return findings;
  },
};

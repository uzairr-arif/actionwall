# ActionWall — Architecture

## 1. Bird's-eye view

```mermaid
flowchart LR
    A[AI Agent] -->|Action| E[ShieldEngine]
    P[(Policy YAML)] -->|loadPolicy + zod| E
    E --> S1[toolPermissions]
    E --> S2[commandRisk]
    E --> S3[filePolicy]
    E --> S4[secrets]
    E --> S5[urlPolicy]
    E --> S6[injection]
    S1 & S2 & S3 & S4 & S5 & S6 -->|Finding[]| AGG[Aggregate + thresholds]
    AGG -->|Decision| D[ALLOW / BLOCK / ASK_HUMAN]
    AGG -->|append| L[(Audit JSONL\nhash chain)]
    D --> T[Tool executor\nonly if not BLOCK]
```

ActionWall is a **library first**. The engine is a pure(ish) function: `(Action, Policy) → Decision`, plus an audit side-effect. The CLI and demo are thin layers on the same API.

## 2. Data model (src/core/types.ts)

- **Action** — what the agent wants: `{ id, timestamp, agentId, tool, params, context }`.
  `tool` is a canonical name (`shell`, `file.read`, `http.request`, …). `context.toolOutput` carries untrusted external content for injection scanning.
- **Finding** — one violation: `{ scanner, ruleId, severity, title, reason, policyRef, evidence }`. Evidence is always redacted and truncated.
- **Decision** — `{ verdict, risk, findings, summary, latencyMs, timestamp }`.
- **Verdict mapping** — policy `risk_thresholds`: severities in `block` → BLOCK, in `ask` → ASK_HUMAN, otherwise ALLOW.

## 3. The pipeline (src/core/engine.ts)

1. Run every scanner in order: toolPermissions → commandRisk → filePolicy → secrets → urlPolicy → injection. (Permissions first — the cheap coarse gate; content scanners next.)
2. Aggregate: decision risk = max finding severity (LOW if none).
3. Map through `risk_thresholds`.
4. Append to the audit log (unless disabled or ALLOW with `log_allowed: false`).

**Failure semantics.** A scanner that throws produces a synthetic finding `SCANNER-FAILURE` — CRITICAL (block) when `fail_closed: true` (default), LOW when fail-open. An audit write failure does not lose the decision; it appends an `AUDIT-WRITE-FAILURE` finding. Rationale: a firewall that crashes open is worse than no firewall, but operators must be able to opt out explicitly for availability-critical paths.

## 4. Scanner contract

```ts
interface Scanner {
  name: string;
  scan(action: Action, policy: PolicyDoc): Finding[];
}
```

Rules for implementations:
- **Pure** — no command execution, no network. Read-only filesystem access is allowed where the scanner's purpose demands it (bulk-delete counting) and must be bounded.
- **Return []** for anything not applicable (e.g. commandRisk on an http.request).
- **Redact evidence** — anything resembling a credential passes through `redactText()`.
- **Cite policy** — findings set `policyRef` so the report can point at the exact knob.

### Adding a scanner

1. Implement the contract (drop it in `src/scanners/`).
2. Add it to `DEFAULT_SCANNERS` in `src/core/engine.ts` (or inject via `new ShieldEngine(policy, { scanners })`).
3. Add tests + a row in REQUIREMENTS/README.

This is also the extension seam for ML-based classifiers (e.g. a small model scoring injection likelihood) — they return findings like any rule-based scanner.

## 5. Key design decisions

### D1 — Rule-based first, ML later
Rules are deterministic, testable, fast (~1–5 ms), auditable, and explainable. For a *firewall* (a control-plane component), "why was this blocked?" must have an exact answer. ML classifiers are a great **addition** (pluggable scanner) but a poor foundation: non-deterministic, unexplainable, and gameable.

### D2 — Analyze, never execute
The shell tokenizer (`util/shell.ts`) is quote-aware and handles chains (`&&`, `;`, `||`, `|`) so each segment is inspected; a fork bomb is matched on the full command because it spans operators. We deliberately do not resolve commands "the way bash would" beyond tokenization — deeper emulation adds complexity and new bypasses; the residual ambiguity is handled by conservative rules (e.g. command substitution = MEDIUM, eval = HIGH).

### D3 — Count, don't guess, for bulk deletes
The headline policy ("no more than 10 automatic deletions") is enforced by **actually counting** the files a glob would remove via a bounded, read-only walk (`util/paths.ts`: 5000-entry cap, depth 12, glob expansion). Severity escalates to CRITICAL when the count exceeds the limit. This turns an intention-based rule ("destructive") into a measurable one ("12 > 10").

### D4 — Path normalization against traversal & platform drift
All paths are home-expanded, resolved, and normalized to POSIX form with any Windows drive prefix stripped before matching (`/etc/**` and `~/.ssh/**` work everywhere). Because matching happens on the *resolved* path, `../../` traversal is defeated by construction — the resolved location is what gets policy-checked. Protected-path rules are first-match-wins so ordering is explicit in the policy file.

### D5 — Secrets: signatures + entropy + redaction everywhere
Well-known formats (AWS, GitHub, OpenAI, Stripe, Slack, JWT, PEM blocks) are regex signatures; unknown formats are covered by a Shannon-entropy heuristic (≥ 32 chars, entropy ≥ 4.0 → MEDIUM). Placeholder values (`changeme`, `${DB_PASS}`) are filtered to avoid alert fatigue. Critically, the same pattern set drives **log redaction** — the audit trail can't store what the scanner would have blocked.

### D6 — SSRF guard with a metadata-endpoint special case
`169.254.169.254` (and GCP/Aliyun equivalents) get CRITICAL because that's the canonical cloud-credential-theft path for compromised agents; the rest of RFC1918/loopback/link-local gets HIGH. Domain allow/deny lists support `*.example.com` wildcards; an empty allowlist means "any public domain".

### D7 — Tamper-evident audit, not tamper-proof
JSONL records hash-chain to their predecessor (`hash = sha256(prevHash + record)`); `log --verify` re-walks the chain and names the first broken entry. A local attacker with filesystem write access can still rewrite the *whole* file consistently (they'd need to recompute every hash — feasible), so this is **tamper-evident**, not tamper-proof. Full integrity would need an external anchor (append-only remote sink, signing key in an HSM) — see ROADMAP.

### D8 — Fail-closed defaults, explicit escapes
Deny wins over allow in tool permissions; deny-by-default is one flag away; scanner crashes block. Everything that opens the firewall (`fail_open`, `allow_outside_workspace`, `log_allowed: false`) is an explicit, greppable policy decision.

## 6. Latency budget

| Stage | Typical |
|---|---|
| Scanner runs (6) | 0.7–5 ms |
| Bulk-delete counting | bounded walk; skipped when a rootish target already blocks |
| Audit append | ~0.1–1 ms (sync appendFile, one line) |
| **Total** | **< 10 ms typical, < 50 ms p95 budget (NFR-1)** |

## 7. Module map

| Module | Responsibility |
|---|---|
| `core/types.ts` | Data model + severity aggregation |
| `core/policy.ts` | YAML/JSON loading, zod validation, safe defaults |
| `core/engine.ts` | Pipeline, thresholds, fail-closed, audit wiring |
| `core/audit.ts` | JSONL append, hash chain, verify, tail |
| `scanners/*` | One file per scanner, contract above |
| `util/shell.ts` | Quote-aware tokenizer, segment splitter, redirect parsing |
| `util/paths.ts` | Home expansion, POSIX normalization, glob→regex, bounded counting |
| `util/secretPatterns.ts` | Signature table + redaction (shared by scanner and logger) |
| `cli/*` | Commander wiring + colored report formatting |
| `demo/mockAgent.ts` | Scripted 9-step agent used by `demo` |

## 8. What v1 does *not* do (pointers)

See THREAT_MODEL.md for the honest limits (obfuscated payloads, homoglyph attacks, shell emulation depth, whole-file rewriting of the audit chain) and ROADMAP.md for where those get addressed.

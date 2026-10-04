# ActionWall — Requirements Specification

Version 1.0 · Status: implemented (v0.1.1) · Identified functional and non-functional requirements, each with acceptance criteria mapped to the test suite.

## 1. Problem statement

AI agents execute tools autonomously: shell commands, file writes, HTTP requests, third-party APIs. A compromised prompt (prompt injection), a hallucinated action, or a bug can cause irreversible damage — deleted files, leaked credentials, SSRF into cloud infrastructure. Existing safeguards (model guardrails, provider "safety" layers) are probabilistic and sit *inside* the model. There is no deterministic, auditable, policy-driven control point between the agent and its tools.

## 2. Goals & non-goals

**Goals**
- G1: Deterministic, inspectable policy enforcement on every agent action before execution.
- G2: Human-readable explanations for every decision (risk, reason, matched policy).
- G3: Tamper-evident audit trail of all decisions.
- G4: Drop-in integration: a pure function from (action, policy) → decision, no framework lock-in.
- G5: Zero network calls and zero command execution inside the firewall itself.

**Non-goals (v1)**
- Running as a network proxy (planned — see ROADMAP).
- Stopping a *determined* adversary with arbitrary obfuscated payloads; ActionWall raises the floor and adds auditability, it is not a sandbox (see THREAT_MODEL).
- Replacing OS-level sandboxing (containers, users, seccomp). It complements them.

## 3. Functional requirements

### 3.1 Decision pipeline

| ID | Requirement | Acceptance criteria |
|---|---|---|
| FR-1 | Engine accepts an Action `{tool, params, agentId, context}` and returns a Decision `{verdict, risk, findings[], summary, latencyMs}`. | `engine.test.ts` — clean action yields `ALLOW`, risk `LOW`, latency ≥ 0. |
| FR-2 | Verdicts are exactly `ALLOW`, `BLOCK`, `ASK_HUMAN`. | All tests assert one of three values. |
| FR-3 | Severity levels are `LOW < MEDIUM < HIGH < CRITICAL`; the decision's risk is the worst finding. | FR-1 + scanner tests. |
| FR-4 | Policy maps severities → verdicts (`risk_thresholds.block` / `.ask`). | `engine.test.ts` custom thresholds: HIGH→ASK when configured. |
| FR-5 | Fail-closed: a scanner exception produces a CRITICAL finding (action blocked). Fail-open is opt-in. | `engine.test.ts` broken-scanner cases. |
| FR-6 | Decisions are computed without executing the action or making network calls. | Code review; unit tests run offline. |

### 3.2 Scanners

| ID | Scanner | Requirement | Acceptance criteria |
|---|---|---|---|
| FR-7 | toolPermissions | Allow/deny lists with `*` wildcards, global or per-agent; deny wins over allow; deny-by-default mode. | `toolPermissions.test.ts`. |
| FR-8 | commandRisk | Tokenize shell commands (quote-aware, chain/pipeline aware) without executing; detect destructive FS ops, privilege escalation, pipe-to-shell, reverse shells, fork bombs, raw device writes, env dumps, obfuscation, custom regex patterns. | `commandRisk.test.ts` (13 cases). |
| FR-9 | commandRisk | **Bulk-delete rule:** expand `rm` targets against the real filesystem (read-only) and block when the count exceeds `file_policy.max_bulk_delete`. | `commandRisk.test.ts` — 12 files with limit 10 → CRITICAL, evidence names the count. |
| FR-10 | filePolicy | Protected-path rules (`deny` / `readonly` / `allow`, first match wins) applied to `file.*` tools **and** file-touching shell commands; workspace containment for reads/writes/deletes. | `filePolicy.test.ts`. |
| FR-11 | secrets | Detect known credential formats + credential assignments (with placeholder filtering) + high-entropy tokens in tool args; never emit the raw secret in findings. | `secrets.test.ts` — AWS/GitHub/OpenAI/private-key/JWT cases; redaction assertions. |
| FR-12 | urlPolicy | Scheme allowlist, domain allow/deny lists with wildcards, private-network & cloud-metadata SSRF guard; applies to web tools and to URLs inside shell commands. | `urlPolicy.test.ts`. |
| FR-13 | injection | Heuristic detection of instruction overrides, fake system markers, prompt-extraction, markdown-image exfiltration, hidden characters, in `toolOutput` and `userPrompt`; N distinct patterns escalate MEDIUM→HIGH. | `injection.test.ts`. |

### 3.3 Audit

| ID | Requirement | Acceptance criteria |
|---|---|---|
| FR-14 | Every decision (including ALLOW, configurable) is appended to daily JSONL files with action params, verdict, risk, findings. | `cli.test.ts` — check writes to `.actionwall/audit/`. |
| FR-15 | Records are hash-chained (SHA-256 over prev hash + record); `verify` re-walks the chain and pinpoints the first broken entry. | `audit.test.ts` + `cli.test.ts` tamper case. |
| FR-16 | Secrets in logged params are redacted. | `audit.test.ts`. |

### 3.4 CLI

| ID | Requirement | Acceptance criteria |
|---|---|---|
| FR-17 | `check <command-or-json>` with `--tool/--params/--context/--agent/--policy/--json/--no-log`. | `cli.test.ts`. |
| FR-18 | Exit codes: 0 allow, 1 block, 3 ask-human, 2 error — CI usable. | `cli.test.ts`. |
| FR-19 | `validate`, `log [--last N] [--verify]`, `demo`. | `cli.test.ts`. |

## 4. Non-functional requirements

| ID | Requirement | Measured |
|---|---|---|
| NFR-1 | **Latency:** a decision completes in < 50 ms at p95 for typical actions on a dev machine (observed: ~1–5 ms; bulk-delete counting is bounded by walk caps). | Decision.latencyMs. |
| NFR-2 | **Safety of the firewall:** never executes commands, never performs network I/O, never writes outside its audit dir. Filesystem access is read-only (readdir/stat) and bounded (5000 entries, depth 12). | util/paths.ts caps. |
| NFR-3 | **Fail-closed by default**, configurable per policy. | FR-5. |
| NFR-4 | **Determinism:** same action + policy + filesystem state ⇒ same decision (no randomness in scanners). | By construction; unit tests. |
| NFR-5 | **Portability:** Linux, macOS, Windows (drive-letter normalization, home expansion). | Tests run on Windows; CI matrix. |
| NFR-6 | **Dependency hygiene:** 3 runtime dependencies (commander, yaml, zod), zero for the core engine. | package.json. |
| NFR-7 | **Explainability:** every finding carries ruleId, human-readable reason, and the policy reference that triggered it. | All scanner tests. |
| NFR-8 | **Test coverage:** every scanner, the engine, audit, policy loader, and CLI have automated tests (76 as of v0.1.1). | `npm test`. |

## 5. Personas

- **Agent developer** — integrates ActionWall into a tool loop; wants `guard()` and clear errors.
- **Security/platform engineer** — writes policies and reviews the audit log; wants `validate` and `log --verify`.
- **Operator/agent owner** — receives ASK_HUMAN escalations and approves or denies.

## 6. Acceptance scenario (product pitch parity)

> Agent wants to execute `rm -rf /project/*` where the glob resolves to 12 files.

Expected: verdict `BLOCK`, risk `CRITICAL`, title "Destructive filesystem operation", reason cites the 12-file count and `file_policy.max_bulk_delete = 10`. ✔ Implemented and demoed by `examples/demo-block-rm-rf.ts` and `actionwall demo` step 9.

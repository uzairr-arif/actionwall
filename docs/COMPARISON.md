# ActionWall — Competitive Landscape

> Research snapshot: October 2026. Refresh before launch — this space moves fast (see the [GitHub `ai-firewall` topic](https://github.com/topics/ai-firewall) for new entrants). Links go to primary sources where possible.

**Purpose:** establish that ActionWall's niche is deliberate, not accidental. The one-line summary:

> "Existing tools mostly scan the *text* going into the model, or sandbox the *runtime* ActionWall works at the layer in between: the **action** the agent is about to take. It's a deterministic, TypeScript-first, policy-as-code control point that any tool-calling loop can embed, with a measured blast radius per action and a tamper-evident audit trail."

## The layer cake

```
┌──────────────────────────────────────────────────────────────┐
│ OS sandbox / container (E2B, Firecracker, Docker)            │  hard isolation,
│                                                              │  coarse grain
├──────────────────────────────────────────────────────────────┤
│ ★ ACTION POLICY LAYER — ActionWall lives here               │  deterministic,
│   (tool calls, commands, file ops, URLs, secrets)            │  per-action,
│                                                              │  explainable
├──────────────────────────────────────────────────────────────┤
│ Text guardrails (Llama Guard, Prompt Guard 2, Rebuff,        │  probabilistic,
│   NeMo Guardrails, Lakera)                                   │  content-level
├──────────────────────────────────────────────────────────────┤
│ Model provider safety filters (OpenAI / Anthropic built-ins) │  opaque, remote
└──────────────────────────────────────────────────────────────┘
```

Most public effort has gone into the *bottom* layers (scanning text) and the *top* layer (sandboxing). The middle layer — deterministic per-action policy — is where ActionWall plays, and it composes with the others rather than replacing them.

## Comparison table

| Project | Shape | What it inspects | Strength | Gap ActionWall fills |
|---|---|---|---|---|
| **Meta Llama Guard / Prompt Guard 2** | model-based classifier | prompts & responses (text) | industry-standard content classification; fast small models | probabilistic, not explainable; benchmarked weak on *indirect* injection ([promptfoo's finding](https://www.promptfoo.dev/lm-security-db/vuln/llm-guardrail-benchmark-lies-10b59e81/)); no tool-action policy, no audit trail, requires model hosting |
| **Rebuff** | detection framework | prompt text (heuristics + LLM + canary tokens + vector DB) | layered injection detection, canary-token exfil proofing | Python, LLM-dependent; text-level only — says nothing about what the agent *does* next |
| **NVIDIA NeMo Guardrails** | guardrail orchestration (Colang) | conversation flows; can wrap other detectors | mature, flexible rails, big ecosystem | dialog-centric; Python; policies are conversational, not per-tool-action with policy files + exit codes |
| **Meta LlamaFirewall** | agent security framework | multi-step agent workflows, content | major-vendor backing, broad scope | Python-first; heavier footprint; not an embeddable TS library with a CLI/audit-verify story |
| **Agent-Wall** (MCP) | MCP client↔server proxy | tool calls passing through MCP | drop-in protection for MCP agents without code changes | deployment = infrastructure proxy, MCP-transport-scoped; ActionWall is an embeddable library + CLI across *all* tool shapes (shell, file.*, http.*) with filesystem-measured rules |
| **@goplus/agentguard** (npm, v1.2.1, active — 27 releases) | TS guard library + Claude Code skills / MCP hooks | dangerous commands, data leaks, secrets; "20 detection rules, runtime action evaluation, trust registry" | closest npm overlap; actively maintained; backed by GoPlus (a web3 security company); MIT | web3/vendor-flavored (ships axios network calls, a trust registry, Claude-Code/MCP orientation); ActionWall's differentiation to defend: offline & dependency-light, framework-agnostic `(Action, Policy) → Decision` API, filesystem-measured bulk-delete, policy-as-code with zod + CI exit codes, hash-chained audit with `--verify` |
| **agentgate** (npm, v0.16.0, ISC) | agent API gateway | reads execute immediately, **writes queue for human approval** | independently arrived at the ASK_HUMAN idea — external validation that human-in-the-loop is the right primitive | gateway-shaped (transport level, its own client model), not an embeddable content-aware policy engine with shell/file/secret scanners |
| **agent-firewall** (npm) | agent↔LLM proxy | loop detection, prompt caching, budget caps | operational cost/behavior controls | different problem (cost & runaway loops), not security policy on tool actions |
| **promptfoo** | eval / red-team harness | your entire guardrail stack | perfect complement: adversarial testing of guardrails in CI | not a runtime control — pair it: promptfoo tests ActionWall's policies |
| **E2B / container sandboxes** | execution isolation | everything inside the sandbox | hard guarantees, real isolation | coarse grain — no explainable per-action verdicts, no policy files, heavy ops; ActionWall complements (see THREAT_MODEL deployment stack) |
| **Framework-native approvals** (Claude Code permission prompts, etc.) | UX-level prompts | each tool call | zero setup, human in the loop | not policy-as-code, no programmatic audit export, per-app behavior; ActionWall makes the same idea deterministic, configurable, and logged |

## Positioning statement (for README/launch)

ActionWall is **not** another prompt-injection scanner and **not** a sandbox. It is a deterministic **action policy layer** for AI agents: `(Action, Policy) → ALLOW / BLOCK / ASK_HUMAN`, TypeScript-first, embeddable in any tool-calling loop or runnable as a CLI, with severity thresholds, a measured blast radius (it counts what a delete would actually remove), fail-closed defaults, and a hash-chained audit log. It composes with text guardrails (which catch what it can't parse) and sandboxes (which bound what it misses).

## Key differentiators

1. **Action-level, deterministic, explainable** — every block cites a rule ID and the exact policy knob (`file_policy.max_bulk_delete`), unlike classifier verdicts.
2. **Measured blast radius** — `rm -rf <glob>` is evaluated by counting real files (bounded walk), turning "destructive" from an opinion into a number.
3. **TypeScript-first** — most guardrail frameworks are Python-first; the JS agent ecosystem (LangChain.js, Vercel AI SDK, TS MCP servers) is underserved.
4. **Policy-as-code** — YAML + zod validation + `actionwall validate` in CI + exit codes built for pipelines.
5. **Tamper-evident audit** — SHA-256 hash chain with `log --verify`, secrets redacted at write time.
6. **Honest scope** — documented limitations (THREAT_MODEL §6) instead of "prevents prompt injection" claims.

## Key sources

- [GitHub topic: ai-firewall](https://github.com/topics/ai-firewall) — running index of AI security gateways (HTTP + MCP)
- [promptfoo LLM Security DB: guardrail benchmark limitations](https://www.promptfoo.dev/lm-security-db/vuln/llm-guardrail-benchmark-lies-10b59e81/) — indirect-injection failures in Llama Guard 3 / Prompt Guard 2
- [promptfoo: testing guardrails guide](https://www.promptfoo.dev/docs/guides/testing-guardrails/) — methodology for benchmarking guardrails (missed attacks vs false positives)
- [arXiv 2502.15427: benchmarking guardrails against prompt injection](https://arxiv.org/html/2502.15427v1) — detection gains vs false-positive costs for NeMo-style rails
- [Snyk: Nx malicious package weaponizing AI coding agents](https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/) — the incident class that motivates action-level controls
- [GMI Cloud: guardrails in production](https://www.gmicloud.ai/en/blog/llm-guardrails-in-production-content-filtering-jailbreak-detection-and-why-guardrails-alone-are-not-enough) — production pattern of stacking a fast classifier under an orchestration layer

## Evaluating the landscape: key questions, answered (verified against the npm registry, October 2026)

Answers to the standard competitor-evaluation questions, with the evidence basis noted. Claims about other packages come from their npm metadata and published descriptions, not source audits.

**What do they do?** The space splits into five shapes: *text classifiers* (Llama Guard, Prompt Guard 2 — score the words going into and out of the model), *detection frameworks* (Rebuff — layered injection detection with canary tokens), *conversation frameworks* (NeMo Guardrails — Colang rules around dialog), *proxies/gateways* (agent-firewall for cost/loops, agentgate for write approvals, Agent-Wall for MCP transport), and *sandboxes* (E2B, containers — isolate execution). Adjacent-but-different: `agentshield` on npm is a hardlink *backup/rollback* tool (acts after the damage), and promptfoo is an eval harness, not a control.

**What don't they do?** No verified package combines: an in-process deterministic verdict on the individual tool action + a filesystem-*measured* blast radius (counting what a delete would remove) + policy-as-code validated at load + a hash-chained, verifiable audit log + a TypeScript-first API. Each tool covers one layer; the action-policy layer with measurement is the open niche.

**Are they difficult to configure?** Classifiers require model hosting or a paid API per call; NeMo requires learning Colang; proxies require running infrastructure. ActionWall: zero-config safe defaults, one optional YAML file, `actionwall validate` for CI.

**Do they support only one framework?** Framework-native approvals are per-app by definition; MCP proxies cover only MCP transports; agentgate assumes its gateway client. ActionWall's contract is one function call from any tool-calling loop.

**Runtime library or CLI?** Most packages are one or the other. ActionWall ships both, plus CI-friendly exit codes (0/1/3/2) and a `demo` command.

**Do they protect filesystem operations?** Sandboxes contain coarsely; the npm `agentshield` restores after deletion; none count the actual blast radius of a delete before deciding. That measurement (12 files > policy limit of 10 ⇒ CRITICAL) is ActionWall's most defensible unique mechanic.

**Do they protect shell commands?** @goplus/agentguard blocks "dangerous commands" (20 rules, per its description). ActionWall's depth: quote-aware tokenization, chain/pipeline-aware analysis, ~15 rule families (reverse shells, fork bombs, obfuscation, raw device writes…), each finding citing a rule ID and the exact policy knob.

**Do they address prompt injection?** The classifier tier is crowded (Llama Guard, Prompt Guard, Rebuff, Lakera…) and benchmarked weak on *indirect* injection. ActionWall doesn't compete there: it detects common textual patterns and — the real defense — constrains what an injected agent can *do*. Even a perfect classifier can't stop a hallucinated `rm -rf`; someone must judge the action.

**Do they have good TypeScript support?** The systemic gap: the major frameworks are Python-first. The JS/TS agent ecosystem (LangChain.js, Vercel AI SDK, TS MCP servers) has essentially one TS-native option (@goplus/agentguard, web3-oriented). This is the clearest market gap ActionWall fills.

**Are their APIs cumbersome?** Classifier APIs are async, remote, and metered per call. ActionWall: `engine.check(action)` — synchronous, local, ~1–5 ms, zero network.

**Are they actively maintained?** @goplus/agentguard: yes (27 releases). agent-firewall: rapid successive releases (churn risk). The big frameworks: maintained by Meta/NVIDIA. Honest caveat that applies to ActionWall too: single-maintainer projects carry bus-factor risk — mitigated here by a tiny dependency surface and deep docs.

**Do they have good tests?** Directly verifiable only for ActionWall (76 tests covering every rule, tamper detection, CLI exit codes). For competitors, the check is CI badges and repo inspection — a question to ask *them*.

**Can ActionWall provide a simpler developer experience?** Yes — that is the pitch: deterministic defaults that work with zero config, a sync API, a 30-second `npx actionwall demo`, human-readable verdicts, and a verifiable audit trail. Simple to adopt, honest about limits, measurable when it blocks.

### Naming provenance (npm registry, verified 2026-10-01)

`agentshield` — taken (backup tool, tomsun28) · `agent-firewall` — taken (LLM proxy) · `agentward` — squatted by a placeholder package · `agentgate` — taken (write-approval gateway) · **`actionwall` — free, adopted** · free at time of check: `toolward`, `agentmoat`, `agentcage`.

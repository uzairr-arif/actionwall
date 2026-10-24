# ActionWall: Roadmap

## v0.1 (current)

- Core engine: 6 scanners, YAML/JSON policies with zod validation, fail-closed defaults
- CLI: check / validate / log / demo, CI-friendly exit codes
- Hash-chained JSONL audit log with `--verify`
- 76 tests; presets: default / strict / readonly

## v0.2: integration depth

- [x] **HTTP service mode** (`actionwall serve`): POST /v1/check with `x-actionwall-verdict` / `x-actionwall-risk` headers, GET /healthz, per-tenant policies via a tenants file (shipped, unreleased)
- [ ] **MCP guard**: run ActionWall as an MCP gateway/proxy so Claude Desktop & friends are protected without code changes
- [ ] Official middleware packages: OpenAI tool-calling, Anthropic tool-use, LangChain/LangGraph, Vercel AI SDK
- [ ] Async audit writer (batched, back-pressured) for high-throughput service mode

## v0.3: smarter detection (shadow-first)

- [ ] Pluggable ML classifier for prompt injection (returns standard Findings; runs in shadow mode first)
- [ ] Per-scanner exceptions/allowlists (`*.pem` allow for a build agent)
- [ ] Configurable rule severities (user-tunable rule table in policy)
- [ ] Homoglyph/confusable detection with per-locale opt-in

## v0.4: operations & trust

- [ ] Real approvals workflow for ASK_HUMAN (queue, TTL, auto-deny, Slack/webhook)
- [ ] Remote audit sink (S3 Object Lock / syslog) + periodic signed Merkle checkpoints, tamper-*proof* rather than tamper-evident
- [ ] `actionwall replay`: re-run past actions under a new policy ("what would have been blocked?")
- [ ] Metrics endpoint (Prometheus): decisions, verdicts, rule hits, latency histograms

## v1.0: hardening

- [ ] Differential shell parsing (exchange the tokenizer for a battle-tested parser behind the same interface)
- [ ] Policy inheritance & org/team composition
- [ ] Fuzzing harness for the tokenizer and glob walker
- [ ] WASM build for browser/edge agent runtimes

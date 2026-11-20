# ActionWall: Roadmap

Milestones record what shipped. Versions snapshot the work at release time, so unfinished items simply carry forward.

## Shipped

### v0.1
- Core engine: 6 scanners, YAML/JSON policies with zod validation, fail-closed defaults
- CLI: check / validate / log / demo, CI-friendly exit codes
- Hash-chained JSONL audit log with `--verify`
- Presets: default / strict / readonly

### v0.2
- HTTP service mode (`actionwall serve`): POST /v1/check with `x-actionwall-verdict` / `x-actionwall-risk` headers, GET /healthz, per-tenant policies via a tenants file
- Dependency refresh: commander 15, zod 4, vitest 5, typescript 7, @types/node 26

### v0.3 (current)
- Rule tuning: `rules.severities` overrides and `rules.exceptions` evidence-scoped suppression
- Homoglyph and mixed-script evasion detection in the injection scanner
- Pluggable injection classifier with shadow and enforce modes (keyword baseline included)

## Next

- [ ] **MCP guard**: run ActionWall as an MCP gateway/proxy so Claude Desktop and friends are protected without code changes
- [ ] Official middleware packages: OpenAI tool-calling, Anthropic tool-use, LangChain/LangGraph, Vercel AI SDK
- [ ] Async audit writer (batched, back-pressured) for high-throughput service mode
- [ ] Approvals workflow for ASK_HUMAN (queue, TTL, auto-deny, Slack/webhook)
- [ ] Remote audit sink (S3 Object Lock / syslog) + periodic signed Merkle checkpoints

## Exploring

- [ ] `actionwall replay`: re-run past actions under a new policy ("what would have been blocked?")
- [ ] Metrics endpoint (Prometheus)
- [ ] Homoglyph coverage expansion: fuller Unicode confusables tables
- [ ] Real-model benchmarking for the injection classifier
- [ ] Differential shell parsing (exchange the tokenizer behind the same interface)
- [ ] Policy inheritance and org/team composition
- [ ] Fuzzing harness for the tokenizer and glob walker
- [ ] WASM build for browser/edge agent runtimes

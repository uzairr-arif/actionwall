# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — 2026-09-14

### Added
- Core decision engine: `(Action, Policy) → ALLOW / BLOCK / ASK_HUMAN` with severity aggregation and fail-closed defaults.
- Six scanners: toolPermissions (wildcards, deny-by-default, per-agent overrides), commandRisk (quote-aware shell analysis, bulk-delete counting, pipe-to-shell, reverse shells, privilege escalation, obfuscation), filePolicy (protected paths, workspace containment, traversal-proof matching), secrets (signature + entropy detection with redaction), urlPolicy (schemes, domain lists, SSRF/metadata guard), injection (override/exfil/hidden-character heuristics).
- YAML/JSON policy loader with zod validation and safe defaults; presets `default`, `strict`, `readonly`.
- Tamper-evident audit log: daily JSONL files, SHA-256 hash chain, `--verify`, automatic secret redaction.
- CLI: `check`, `validate`, `log`, `demo` with CI-friendly exit codes (0/1/3/2).
- Scripted demo agent (`actionwall demo`) — 9 actions: 3 allowed, 1 escalated, 5 blocked.
- 76 unit/integration tests (vitest); GitHub Actions CI on Node 20/22/24.
- Documentation: README, REQUIREMENTS, ARCHITECTURE, THREAT_MODEL, POLICY_REFERENCE, COMPARISON, ROADMAP.

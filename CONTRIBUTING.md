# Contributing to ActionWall

Thanks for helping make agents safer. This project keeps a professional bar: typed, tested, documented.

## Development setup

```bash
npm install
npm test          # vitest (76 tests)
npm run typecheck # tsc --noEmit, strict
npm run build     # emit dist/
npm run demo      # scripted agent behind the firewall
```

CI runs typecheck + tests on Node 20/22/24.

## Ground rules

1. **The firewall never executes actions and never makes network calls.** Read-only, bounded filesystem access is allowed only where a scanner's purpose requires it (bulk-delete counting) — keep caps in `util/paths.ts`.
2. **Every finding must be explainable.** New rules need a `ruleId`, a human-readable `reason`, and a `policyRef` pointing at the knob that controls them.
3. **Redact everything.** If a rule can match a credential, its evidence must pass through `redactText()`.
4. **Fail closed by default.** Anything that opens the firewall (allowlists, fail-open) must be an explicit policy flag, documented in POLICY_REFERENCE.
5. **Tests required.** New rule → unit test with both a positive (caught) and negative (benign pass-through) case. Bug fix → regression test first.
6. **Update docs** in the same PR: REQUIREMENTS (FR/NFR row), POLICY_REFERENCE (if policy surface changed), THREAT_MODEL (if the threat surface changed).

## Adding a scanner

See "Adding a scanner" in docs/ARCHITECTURE.md — implement the `Scanner` contract, register it (or document injection via `ShieldEngine({scanners})`), test it, document it.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`) keep the changelog easy to maintain.

## Reporting vulnerabilities

Please do not open public issues for exploitable bypasses. Open a GitHub security advisory instead.

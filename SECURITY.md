# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

**Please do not open public issues for exploitable policy bypasses.**

Use GitHub's [private security advisories](https://github.com/security/advisories) ("Report a vulnerability" on the repository's Security tab), or contact the maintainers directly if you cannot use GitHub.

Include:
- The ActionWall version and policy configuration (redact real secrets/domains)
- A minimal reproduction: the action, the policy, and the observed vs. expected verdict
- Your assessment of impact

## What's in scope

- Policy bypasses: an action that violates the spirit of a policy but receives ALLOW/ASK_HUMAN
- Shell tokenizer evasions that defeat command-risk analysis
- Path normalization failures (traversal, home expansion, drive-prefix handling)
- Secret-detection misses that leak credentials into tool arguments or the audit log
- Audit-log integrity: chain verification failing to detect tampering

## What's out of scope

- Attacks requiring a compromised host OS or agent runtime (see docs/THREAT_MODEL.md — ActionWall is a policy gate, not isolation)
- Prompt-injection techniques that do not result in a policy-relevant action
- Denial of service against the ActionWall process itself in shared environments

## Response targets

- Acknowledgment: within 3 business days
- Triage and severity assessment: within 7 days
- Fix or mitigation for high-severity issues: within 30 days

Thanks for helping make agent security tooling trustworthy — disclosure like this makes the whole ecosystem better.

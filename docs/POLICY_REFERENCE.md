# ActionWall — Policy Reference

Policies are YAML (or JSON) documents validated with zod at load time. **Every field is optional** — omitted sections fall back to the built-in defaults shown in `policies/default.yaml`. Invalid fields fail loudly (`actionwall validate`).

```bash
actionwall validate --policy policies/strict.yaml
```

## Top level

| Field | Type | Default | Meaning |
|---|---|---|---|
| `version` | `1` | `1` | Schema version. |
| `name` | string | `"default"` | Policy name, shown by `validate`. |
| `description` | string | — | Free text. |
| `fail_closed` | bool | `true` | Scanner crash ⇒ CRITICAL finding (block). Set `false` for fail-open. |
| `risk_thresholds.block` | RiskLevel[] | `[HIGH, CRITICAL]` | Severities that BLOCK. |
| `risk_thresholds.ask` | RiskLevel[] | `[MEDIUM]` | Severities that escalate to ASK_HUMAN. Anything else is ALLOW. |

## `tools`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `default` | `allow` \| `deny` | `allow` | Verdict for tools not on any list. |
| `allow` | string[] | `[]` | Allowed tool names; `file.*` wildcards supported. |
| `deny` | string[] | `[]` | Denied tools. **Deny always wins over allow.** |
| `agents` | map | `{}` | Per-agent override: `agents.<agentId>` may set `default`, `allow`, `deny`. When present, an agent's own lists replace the global ones. |

Example — a junior agent that may only read and search:

```yaml
tools:
  default: allow
  agents:
    intern-agent:
      default: deny
      allow: [file.read, web.search]
```

## `command_risk`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `blocked_patterns` | string[] | `[]` | Extra regexes (ECMAScript syntax) hard-blocked on shell commands → HIGH findings. |

```yaml
command_risk:
  blocked_patterns:
    - "docker\\s+system\\s+prune"
    - "kubectl\\s+delete\\s+(?!pod)"   # negative lookahead works too
```

Built-in command rules (not configurable individually — remove the scanner if you need to): rootish `rm` targets, bulk deletes, recursive+force deletion, pipe-to-shell, process-substitution exec, privilege escalation (`sudo`/`su`/`doas`), fork bombs, `dd of=/dev/*`, `mkfs*`, power commands, reverse shells (`nc -e`, `/dev/tcp/`, `socat EXEC:`), env dumps, eval/base64-decode obfuscation, command substitution, `chmod 777`, `git push --force`, remote copies, secret-file reads, custom patterns, overlong commands.

## `file_policy`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `max_bulk_delete` | int ≥ 1 | `10` | Max files one delete action may remove (counted on the real filesystem). Exceeding ⇒ CRITICAL. |
| `protected_paths` | rule[] | 12 rules incl. `.env`, `~/.ssh/**`, `~/.aws/**`, `.git/**`, `/etc/**` (readonly) | First matching rule wins. |
| `workspace_root` | string | process cwd | Root for containment checks. |
| `allow_outside_workspace` | bool | `false` | If false: writes/deletes outside the workspace ⇒ HIGH, reads ⇒ MEDIUM. |

**Path rule** = `{ path, permissions, description? }` where `permissions` is one of:
- `[deny]` — no access at all
- `[readonly]` — reads allowed, writes/deletes blocked
- `[allow]` — everything allowed (use to punch holes in earlier rules)

**Ordering matters** — first match wins:

```yaml
protected_paths:
  - { path: "**",        permissions: [readonly] }  # everything read-only…
  - { path: "**/.env",   permissions: [deny] }      # …but .env is fully denied (must come FIRST)
```

Patterns are globs: `**` crosses directories, `*` stays within one. Paths are home-expanded, resolved (defeating `../` traversal by normalization), and matched in POSIX form with Windows drive letters stripped, so `~/.ssh/**` and `/etc/**` behave identically on all platforms.

## `url_policy`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `allowed_schemes` | string[] | `[https]` | Any other scheme (`http`, `file`, `ftp`) ⇒ HIGH. |
| `allowed_domains` | string[] | `[]` | Empty = any public domain. Non-empty = deny-by-default egress. `*.example.com` matches subdomains and the apex. |
| `denied_domains` | string[] | `[]` | Checked first; wins over the allowlist. |
| `block_private_networks` | bool | `true` | loopback/RFC1918/link-local/`.internal` ⇒ HIGH; cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, …) ⇒ **CRITICAL**. |

Applies to the `http.*`/`web.*`/`browser.*` tool family **and** to URLs inside shell commands (`curl`, `wget`, …), including implicit hosts (`curl example.com` = http scheme).

## `secrets`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `scan_entropy` | bool | `true` | Unknown-token heuristic: ≥ 32 chars, Shannon entropy ≥ 4.0 ⇒ MEDIUM. |
| `custom_patterns` | `{name, regex, severity}[]` | `[]` | Org-specific credential formats. |

```yaml
secrets:
  custom_patterns:
    - { name: internal-jira, regex: "jira_[A-Za-z0-9]{20,}", severity: HIGH }
```

Built-in signatures: AWS access/secret keys, GitHub tokens, OpenAI/Anthropic keys, Stripe live keys, Slack tokens, Google API keys, PEM private-key blocks, JWTs, credential assignments (`password=…` with placeholder filtering). All findings are **redacted** before display and logging.

## `injection`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch. |
| `hits_for_high` | int ≥ 1 | `2` | Distinct patterns in one text before severity escalates MEDIUM → HIGH. |

Scans `context.toolOutput` and `context.userPrompt`. Pattern families: instruction overrides, fake system markers, prompt-extraction requests, role overrides, urgent-execute directives, impersonated assistant turns, markdown-image exfiltration (⇒ HIGH immediately), hidden zero-width characters.

## `audit`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Master switch (also settable via engine options). |
| `log_dir` | string | `.actionwall/audit` | Directory for daily `audit-YYYY-MM-DD.jsonl` files. |
| `redact_secrets` | bool | `true` | Redact credential-looking values in logged params. |
| `log_allowed` | bool | `true` | Record ALLOW decisions too (disable for noise reduction). |

## Full example (strict production policy)

See [`policies/strict.yaml`](../policies/strict.yaml) — deny-by-default tools, egress allowlist, `hits_for_high: 1`, and per-agent restrictions. [`policies/readonly.yaml`](../policies/readonly.yaml) shows the whole-filesystem `**` readonly pattern with deny rules ordered before it.

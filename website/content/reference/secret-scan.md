+++
title = "Secret scanning"
description = "The --secret-scan policies, the built-in detection rules, path allowlisting, and the .gnawconfig keys."
weight = 50
+++

Secret scanning inspects each file's content for likely credentials before
output. See the [how-to](/how-to/scan-for-secrets/) for the task-oriented walk
through; this page is the exhaustive surface.

## Flags

| Flag | Values | Effect |
| --- | --- | --- |
| `--secret-scan` | `off`, `warn`, `redact`, `block` | What to do on a finding (default `warn`) |
| `--secret-scan-allow <FRAGMENT>` | path substring, repeatable | Skip files whose path contains the fragment |

## Policies

| Policy | Content | Findings | Exit |
| --- | --- | --- | --- |
| `off` | unchanged | none (no scan) | 0 |
| `warn` | unchanged | reported on stderr | 0 |
| `redact` | secret → `[REDACTED: <rule>]` | reported on stderr | 0 |
| `block` | file dropped | reported in abort message | non-zero if any found |

`redact` runs before token counting, so redaction shrinks the reported token
total. Previews in reports show only the first few characters plus a length —
the full secret is never printed or logged.

## Detection rules

gnaw scans with the [gitleaks](https://github.com/gitleaks/gitleaks) ruleset
(MIT-licensed), vendored into the binary so scanning is offline and
reproducible — no network calls, no runtime download. Each rule is a regex
plus, for most, a per-rule Shannon-entropy floor: a match below the floor (a
low-entropy documentation example, say) is rejected, which is what keeps
placeholder keys out of the report.

The ruleset is large — a few hundred rules — and covers the credential shapes
you'd expect: cloud providers (AWS, GCP, Azure), source forges (GitHub, GitLab,
Bitbucket), messaging and payments (Slack, Stripe, Twilio, SendGrid), AI vendors
(OpenAI, Anthropic), package registries, PEM private-key blocks, JWTs, and a
family of generic high-entropy assignment rules for `key`/`secret`/`token`/
`password`-named fields. Because it's the upstream gitleaks ruleset, any shape
gitleaks detects, gnaw detects.

A rule fires only when its keyword appears in the file (a fast prefilter), then
the regex and entropy gate confirm the match — so a file with no candidate
keywords is skipped cheaply, and the full ruleset only runs against files that
could plausibly contain a secret.

{% aside(kind="note", title="Staying current") %}
The vendored ruleset is refreshed by a scheduled CI job that pulls the latest
gitleaks release and opens a PR, so coverage tracks upstream without a manual
sync. The exact ruleset version a build ships is stamped into the vendored file.
{% end %}

An allowlist suppresses known false positives — for example AWS's
`AKIAIOSFODNN7EXAMPLE` documentation key — so those won't be reported or
redacted. Rule-level allowlists from the gitleaks ruleset (stopwords like
`EXAMPLE`/`example`, and per-rule path exceptions) are honored as well.

{% aside(kind="note", title="What it catches, and what it can't") %}
Rules anchored on a distinctive prefix (`ghp_`, `AKIA`, `sk-ant-`, …) are the
most reliable — the prefix plus entropy makes a confident match. A secret with
no recognizable prefix is only caught when it appears in a recognizable
assignment (`api_key = "…"`) via a generic rule; a bare, unprefixed,
unassigned blob on its own line won't match, by design, to avoid flooding the
report with false positives. Treat scanning as strong risk reduction, not proof
the output is clean.
{% end %}

## Path allowlist

`--secret-scan-allow` (and the `secret_scan_allow_paths` config key) hold
**substring** fragments, not globs — `tests/` skips any path containing that
segment. When the list is empty, gnaw falls back to a built-in default set:

```text
/tests/   /test/   /fixtures/   /testdata/   /__tests__/   _test.
```

Setting any fragment replaces the defaults entirely — you then own the full
list. Allowlisted files are skipped completely, so a real secret inside one is
not detected.

## .gnawconfig keys

| Key | Type | Default |
| --- | --- | --- |
| `secret_scan` | `"off"` / `"warn"` / `"redact"` / `"block"` | `"warn"` |
| `secret_scan_allow_paths` | array of path-substring strings | built-in test set |

```toml
secret_scan = "redact"
secret_scan_allow_paths = ["tests/", "fixtures/"]
```

Resolution order is **CLI flag → `.gnawconfig` → built-in default**.

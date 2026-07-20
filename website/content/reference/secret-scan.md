+++
title = "Secret scanning"
description = "The --secret-scan policies, the gitleaks-based detection rules, gnaw's deliberate overrides, path allowlisting, and the .gnawconfig keys."
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
| `--scan-threads <N>` | integer, `0` = default | Threads for the scan (see [tuning](#tuning)) |
| `--dfa-cache-mb <MB>` | integer, `0` = default | Per-thread regex DFA cache (see [tuning](#tuning)) |

<!-- REVIEW: confirm --scan-threads / --dfa-cache-mb flag names and that both default to 0 in args.rs. -->

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
`password`-named fields.

gnaw adapts gitleaks' Go (RE2) patterns to Rust's `regex` engine. The two are
close relatives, so the vast majority compile verbatim; a rule that uses a
construct Rust's engine rejects is skipped rather than failing the whole
ruleset, and the compile rate is checked whenever the vendored ruleset is
refreshed.

## Where gnaw deliberately differs from gitleaks

gnaw is **not** a byte-for-byte gitleaks. A few targeted overrides live in
gnaw's code (not the vendored TOML, so they survive ruleset updates), each
trading a specific false positive or false negative:

**Recovered credential families.** gitleaks' `generic-api-key` rule treats the
whole match as the secret and suppresses by *variable name*, which silently
misses `access_token` / `auth_token` / `password` / `client_secret` assignments.
gnaw scopes the rule to the assigned **value** instead, recovering those
families. The cost is that a high-entropy hash sitting in a credential-named
variable could look like a secret — so gnaw pairs the change with a value-shape
allowlist that suppresses md5/sha/UUID/SRI-shaped values. The accepted residual:
a real secret that is *itself* exactly hash- or UUID-shaped gets allowlisted.

**Private keys.** gnaw replaces the vendored `private-key` pattern with one that
requires a full `-----END … PRIVATE KEY-----` marker to close and at least one
full-length base64 run in the body. This does two things the stock pattern
doesn't: it stops a short/truncated placeholder block from lazily consuming a
following real key's `BEGIN` marker (a detection bypass), and it keeps
documentation placeholders — which have no real key material — out of the
report. Modern single-line keys (Ed25519 and similar) are detected.

The practical upshot: gnaw aims to be **more precise on placeholders and more
thorough on real credentials** than the stock ruleset, not merely equal to it.
Where it diverges, it diverges on purpose and in code you can read.

## Tuning

Secret scanning is the memory- and CPU-heavy part of a run. Two flags let you
trade throughput against footprint; both default to a value gnaw picks for you,
and most users never touch them.

| Flag | `0` (default) means | Raise to | Lower to |
| --- | --- | --- | --- |
| `--scan-threads` | auto (a capped share of your cores) | scan faster on a big host | cap memory |
| `--dfa-cache-mb` | built-in default | (rarely needed) | cap per-thread cache |

<!-- REVIEW: confirm the default-resolution wording (auto = min(N, cores)) and the built-in DFA default against secret_scan.rs / gitleaks.rs. -->

The scan runs on a bounded thread pool so it doesn't crowd out the rest of the
pipeline, and rule regexes compile lazily — a rule whose keyword never appears
in your content is never compiled — so scanning a repo that uses few credential
shapes stays cheap.

## Ordering in the pipeline

Scanning runs **after** compression and **before** token counting. So a secret
inside a function body that compression already stripped never reaches the
scanner, and when you `redact`, the reported token total reflects the scrubbed
output.

## Path allowlisting

`--secret-scan-allow <FRAGMENT>` skips any file whose path contains the given
substring; repeat the flag for several fragments. With no fragments supplied,
gnaw uses a built-in set aimed at test and fixture directories, so intentional
fake keys in your test suite don't light up the report. Supplying your own
fragments replaces the built-in set.

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

<!-- REVIEW: --scan-threads / --dfa-cache-mb are intentionally NOT listed as .gnawconfig keys because they were kept CLI-only (not added to TomlConfig). Confirm that's still the case; if you added them to TomlConfig, document them here. -->

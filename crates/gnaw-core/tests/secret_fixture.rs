// crates/gnaw-core/tests/secret_fixture.rs
//! Ground-truth fixture for the secret scanner: does gnaw DETECT the right
//! secrets, GUARD them, and stay quiet on decoys? Two tests:
//!   secret_scanner_ground_truth — detection (scan) against labeled cases.
//!   secret_scanner_guards       — guarding (scrub/redact/warn) removes+reports.
//!
//! Every value is validated against the vendored gitleaks v8.30.1 ruleset with
//! ALL gates simulated to match gnaw's `allowed()`: keyword prefilter, regex,
//! entropy, and stopwords — matched as SUBSTRINGS against the secret, which for
//! `generic-api-key` (no secretGroup) is the WHOLE match, variable name included.
//! That last detail is the whole story of the blind spots below.
//!
//! ── The generic-detector blind spot (the important finding) ──────────────
//! gnaw's inline-credential coverage (generic-api-key) is NARROW by inherited
//! gitleaks design: any assignment whose text contains a stopword is suppressed.
//! FIRES:  api_key, apikey, secret_key, private_key, encryption_key, jwt_secret…
//! BLIND:  access_token, auth_token, *_token, password, db_password,
//!         client_secret, access_key, master_key, webhook_secret …
//! i.e. the entire *_token / password / client_* families pass straight through.
//! This is upstream-faithful (gitleaks misses them too — no generic token rule),
//! but for gnaw's job (guard before an LLM paste) it's a real leak surface.
//! Fix lever: give generic-api-key a secretGroup so stopwords test the VALUE,
//! not the variable name — recovers *_token/password names, keeps value-based
//! suppression. Trade-off: more FPs. Product call, tracked by StopwordGap below.
//!
//! Kinds:
//!   Tp          — MUST be detected (hard-asserted).
//!   StopwordGap — a REAL secret gnaw MISSES by design. Reported, not asserted.
//!                 If one starts firing, coverage changed — promote to Tp.
//!   CleanDecoy  — high-entropy NON-secret that must stay silent (hard-asserted).
//!   ExpectedFp  — genuine noise that DOES fire; the tuning backlog. Reported.
//!
//! Seed for the bench-secret corpus: plant under NON-allowlisted paths (src/,
//! config/ — never tests/ or fixtures/, which the Scrubber path allowlist skips).
//!
//! Run: cargo test -p gnaw-core --test secret_fixture -- --nocapture

use gnaw_core::secret_scan::{SCANNER, SecretPolicy, SecretScanner};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Tp,
    StopwordGap,
    CleanDecoy,
    ExpectedFp,
}
use Kind::*;

struct Case {
    id: &'static str,
    kind: Kind,
    hint: &'static str,
    note: &'static str,
    content: &'static str,
}

const HI: &str = r#"Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa"#; // high-entropy fake value

const CASES: &[Case] = &[
    // ---- Structural TPs: MUST fire via their provider rule ------------------
    Case {
        id: "aws-access-key",
        kind: Tp,
        hint: "aws-access-token",
        note: "",
        content: r#"aws_key = "AKIAQ7RZX4MW2K6TNVBS""#,
    },
    Case {
        id: "github-pat",
        kind: Tp,
        hint: "github-pat",
        note: "",
        content: r#"gh = "ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K""#,
    },
    Case {
        id: "stripe-key",
        kind: Tp,
        hint: "stripe-access-token",
        note: "",
        content: r#"stripe = "sk_live_51H8xQ2eZvKmNpLrWt3Yb9Fd7Gc""#,
    },
    Case {
        id: "slack-bot-token",
        kind: Tp,
        hint: "slack-bot-token",
        note: "",
        content: r#"slack = "xoxb-2334455667-1234567890-Ab9Cd8Ef7Gh6Ij5Kl4Mn3""#,
    },
    Case {
        id: "gcp-api-key",
        kind: Tp,
        hint: "gcp-api-key",
        note: "",
        content: r#"g = "AIzaSyB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uVwX""#,
    },
    Case {
        id: "gitlab-pat",
        kind: Tp,
        hint: "gitlab-pat",
        note: "",
        content: r#"gl = "glpat-Ab9Cd8Ef7Gh6Ij5Kl4Mn""#,
    },
    Case {
        id: "jwt",
        kind: Tp,
        hint: "jwt",
        note: "",
        content: r#"jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N""#,
    },
    Case {
        id: "private-key",
        kind: Tp,
        hint: "private-key",
        note: "",
        content: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\nuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----",
    },
    Case {
        id: "anthropic-key",
        kind: Tp,
        hint: "anthropic-api-key",
        note: "randomized body (alphabet run trips a global stopword)",
        content: r#"a = "sk-ant-api03-R7mK2pX9qL4vT8nB3wZ6cJ1yF5hD0sGaR7mK2pX9qL4vT8nB3wZ6cJ1yF5hD0sGaR7mK2pX9qL4vT8nB3wZ6cJ1yF5hD0AA""#,
    },
    // ---- Generic TP: the DIFFERENTIATOR, using a name that survives ----------
    // `api_key` fires generic-api-key — an inline cred no provider rule covers,
    // the class Secretlint structurally misses. Represents the WORKING subset.
    Case {
        id: "inline-api-key",
        kind: Tp,
        hint: "generic-api-key",
        note: "inline cred; stopword-safe name",
        content: r#"api_key = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    // ---- Stopword blind spots: REAL secrets gnaw MISSES (report, not assert) -
    // The common credential families the generic detector cannot see. Each is a
    // real secret that would leak. Fixing the secretGroup would flip these to Tp.
    Case {
        id: "gap-access-token",
        kind: StopwordGap,
        hint: "stopword: acces",
        note: "access_token — leaks",
        content: r#"access_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "gap-auth-token",
        kind: StopwordGap,
        hint: "stopword: auth/token",
        note: "auth_token — leaks",
        content: r#"auth_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "gap-password",
        kind: StopwordGap,
        hint: "stopword: password",
        note: "password — leaks",
        content: r#"password = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "gap-db-password",
        kind: StopwordGap,
        hint: "stopword: password",
        note: "db_password — leaks",
        content: r#"db_password = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "gap-client-secret",
        kind: StopwordGap,
        hint: "stopword: client",
        note: "client_secret — leaks",
        content: r#"client_secret = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "gap-refresh-token",
        kind: StopwordGap,
        hint: "stopword: refresh",
        note: "refresh_token — leaks",
        content: r#"refresh_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    // ---- Clean decoys: high-entropy NON-secrets that must stay silent --------
    Case {
        id: "uuid-v4",
        kind: CleanDecoy,
        hint: "-",
        note: "",
        content: r#"id = "f47ac10b-58cc-4372-a567-0e02b2c3d479""#,
    },
    Case {
        id: "npm-integrity-hash",
        kind: CleanDecoy,
        hint: "-",
        note: "",
        content: r#""integrity": "sha512-XJ8pQ3nKz2vRwT9mYd4fA6bC1eH0gL7sN2oP5qU8wZ""#,
    },
    Case {
        id: "base64-asset-chunk",
        kind: CleanDecoy,
        hint: "-",
        note: "",
        content: r#"icon = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ""#,
    },
    // silent via keyword prefilter (sourcegraph needs "sgp_"; bare SHA never wakes it)
    Case {
        id: "git-sha-in-comment",
        kind: CleanDecoy,
        hint: "keyword prefilter",
        note: "",
        content: r#"// pinned da39a3ee5e6b4b0d3255bfef95601890afd80709"#,
    },
    // silent via the "cache" stopword — precision face of the gap mechanism
    Case {
        id: "md5-cache-key",
        kind: CleanDecoy,
        hint: "stopword: cache",
        note: "",
        content: r#"cache_key = "d41d8cd98f00b204e9800998ecf8427e""#,
    },
    // ---- Expected FP that DOES fire: hash in a stopword-safe secret-ish var --
    Case {
        id: "md5-in-api-key-var",
        kind: ExpectedFp,
        hint: "generic-api-key",
        note: "MD5 in api_key var — indistinguishable from a cred to the entropy path",
        content: r#"zq_api_key = "d41d8cd98f00b204e9800998ecf8427e""#,
    },
];

fn family_of(hint: &str) -> &str {
    hint.split(&[' ', '-', ':'][..]).next().unwrap_or(hint)
}

#[test]
fn secret_scanner_ground_truth() {
    let mut tp_total = 0usize;
    let mut tp_caught = 0usize;
    let mut clean_total = 0usize;
    let mut clean_kept = 0usize;
    let mut missed_tps: Vec<&str> = Vec::new();
    let mut noisy_cleans: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut fallback_only_tps: Vec<(&str, &str, Vec<&str>)> = Vec::new();
    let mut gap_status: Vec<(&str, &str, bool)> = Vec::new();
    let mut fp_status: Vec<(&str, &str, bool)> = Vec::new();

    println!(
        "\n{:<24} {:<12} {:<9} {:<24} rules",
        "case", "kind", "verdict", "hint"
    );
    println!("{}", "-".repeat(94));

    for c in CASES {
        let ids: Vec<&str> = SCANNER.scan(c.content).iter().map(|f| f.rule_id).collect();
        let fired = !ids.is_empty();
        let by_family = ids.iter().any(|id| id.contains(family_of(c.hint)));

        let (kind, verdict) = match c.kind {
            Tp => {
                tp_total += 1;
                if fired {
                    tp_caught += 1;
                    if by_family {
                        ("Tp", "caught")
                    } else {
                        fallback_only_tps.push((c.id, c.hint, ids.clone()));
                        ("Tp", "caught*")
                    }
                } else {
                    missed_tps.push(c.id);
                    ("Tp", "MISS")
                }
            }
            StopwordGap => {
                gap_status.push((c.id, c.note, fired));
                ("StopwordGap", if fired { "NOW FIRES" } else { "leaks" })
            }
            CleanDecoy => {
                clean_total += 1;
                if fired {
                    noisy_cleans.push((c.id, ids.clone()));
                    ("CleanDecoy", "NOISE")
                } else {
                    clean_kept += 1;
                    ("CleanDecoy", "silent")
                }
            }
            ExpectedFp => {
                fp_status.push((c.id, c.note, fired));
                ("ExpectedFp", if fired { "fires" } else { "silenced" })
            }
        };
        println!(
            "{:<24} {:<12} {:<9} {:<24} {}",
            c.id,
            kind,
            verdict,
            c.hint,
            ids.join(", ")
        );
    }

    println!(
        "\nrecall (TP caught):    {tp_caught}/{tp_total}  ({:.0}%)",
        100.0 * tp_caught as f64 / tp_total.max(1) as f64
    );
    println!(
        "clean precision:       {clean_kept}/{clean_total}  ({:.0}%)",
        100.0 * clean_kept as f64 / clean_total.max(1) as f64
    );

    if !gap_status.is_empty() {
        println!(
            "\n⚠ INLINE-CREDENTIAL BLIND SPOTS — real secrets gnaw leaks (generic-detector stopwords):"
        );
        for (id, note, fires) in &gap_status {
            println!(
                "  - {id}: {note}{}",
                if *fires {
                    "  [NOW FIRES — coverage changed, promote to Tp]"
                } else {
                    ""
                }
            );
        }
        println!(
            "  {} of {} common credential names leak. Fix: secretGroup on generic-api-key.",
            gap_status.iter().filter(|(_, _, f)| !f).count(),
            gap_status.len()
        );
    }
    if !fallback_only_tps.is_empty() {
        println!("\nTPs caught only by a fallback rule (structural rule missed):");
        for (id, hint, ids) in &fallback_only_tps {
            println!("  - {id}  expected {hint}  ->  {}", ids.join(", "));
        }
    }
    if !fp_status.is_empty() {
        println!("\nexpected-FP status (tuning backlog):");
        for (id, note, fires) in &fp_status {
            println!(
                "  - {id}: {}  ({note})",
                if *fires { "FIRES" } else { "silenced" }
            );
        }
    }

    assert!(
        missed_tps.is_empty(),
        "recall regression: secrets went undetected: {missed_tps:?}"
    );
    assert!(
        noisy_cleans.is_empty(),
        "precision regression: clean decoys fired: {noisy_cleans:?}"
    );
}

/// Guarding: detection is useless if the guard doesn't remove/report. Verifies
/// the scrub primitive per policy on a known secret.
#[test]
fn secret_scanner_guards() {
    let line = r#"gh = "ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K""#;
    let raw = "ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K";

    // Redact: the raw secret MUST NOT survive; a marker MUST be present.
    let (redacted, rf) = SCANNER.scrub(line, SecretPolicy::Redact);
    assert!(
        !redacted.contains(raw),
        "redact leaked the secret: {redacted}"
    );
    assert!(
        redacted.contains("[REDACTED:"),
        "redact left no marker: {redacted}"
    );
    assert!(!rf.is_empty(), "redact reported no findings");

    // Warn: content preserved verbatim, findings still reported (the caller acts).
    let (warned, wf) = SCANNER.scrub(line, SecretPolicy::Warn);
    assert_eq!(warned, line, "warn must not alter content");
    assert!(!wf.is_empty(), "warn must still report findings");

    // A blind-spot secret is (correctly, per current design) NOT guarded — this
    // documents the leak at the guard layer too, so it can't hide behind scan().
    let leak = r#"access_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#;
    let (out, f) = SCANNER.scrub(leak, SecretPolicy::Redact);
    if f.is_empty() {
        eprintln!("NOTE: access_token assignment is NOT guarded (stopword blind spot): {out}");
    }
}

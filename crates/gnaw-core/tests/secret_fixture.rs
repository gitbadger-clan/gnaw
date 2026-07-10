// crates/gnaw-core/tests/secret_fixture.rs
//! Ground-truth fixture for the secret scanner: does gnaw DETECT the right
//! secrets, GUARD them, and stay quiet on decoys? Two tests:
//!   secret_scanner_ground_truth — detection (scan) against labeled cases.
//!   secret_scanner_guards       — guarding (scrub/redact/warn) removes+reports.
//!
//! Reflects the gnaw override on generic-api-key (secretGroup=1 + value-shape
//! allowlist, see gnaw_override in gitleaks.rs): stopwords test the VALUE, so the
//! *_token / password / client_* families gitleaks itself misses are RECOVERED;
//! and a value-shape allowlist suppresses the hash/UUID FPs that value-based
//! matching would otherwise introduce.
//!
//! Kinds:
//!   Tp        — MUST be detected (hard-asserted). Includes the recovered
//!               credential families — a deliberate improvement over vanilla
//!               gitleaks, which suppresses them by variable name.
//!   Clean     — must stay silent (hard-asserted): non-secrets AND the
//!               hash/UUID-in-credential-var cases the value allowlist kills.
//!   Residual  — the ACCEPTED cost: a real secret that is itself pure-hex-of-
//!               hash-length or UUID-shaped gets allowlisted. Reported, not
//!               asserted. If one starts firing, the allowlist changed.
//!
//! Every value validated against vendored gitleaks v8.30.1 + the override, with
//! all gates simulated to match gnaw's allowed() (stopwords/value-allowlist vs
//! the captured VALUE).
//!
//! Run: cargo test -p gnaw-core --test secret_fixture -- --nocapture

use gnaw_core::secret_scan::{SCANNER, SecretPolicy, SecretScanner};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Tp,
    Clean,
    Residual,
}
use Kind::*;

struct Case {
    id: &'static str,
    kind: Kind,
    hint: &'static str,
    note: &'static str,
    content: &'static str,
}

const CASES: &[Case] = &[
    // ---- Structural TPs ------------------------------------------------------
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
        note: "",
        content: r#"a = "sk-ant-api03-R7mK2pX9qL4vT8nB3wZ6cJ1yF5hD0sGaR7mK2pX9qL4vT8nB3wZ6cJ1yF5hD0sGaR7mK2pX9qL4vT8nB3wZ6cJ1yF5hD0AA""#,
    },
    // ---- Generic TP + the RECOVERED families (was StopwordGap, now caught) ---
    Case {
        id: "inline-api-key",
        kind: Tp,
        hint: "generic-api-key",
        note: "stopword-safe name",
        content: r#"api_key = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "access-token",
        kind: Tp,
        hint: "generic-api-key",
        note: "RECOVERED via secretGroup=1",
        content: r#"access_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "auth-token",
        kind: Tp,
        hint: "generic-api-key",
        note: "RECOVERED",
        content: r#"auth_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "password",
        kind: Tp,
        hint: "generic-api-key",
        note: "RECOVERED",
        content: r#"password = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "db-password",
        kind: Tp,
        hint: "generic-api-key",
        note: "RECOVERED",
        content: r#"db_password = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "client-secret",
        kind: Tp,
        hint: "generic-api-key",
        note: "RECOVERED",
        content: r#"client_secret = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    Case {
        id: "refresh-token",
        kind: Tp,
        hint: "generic-api-key",
        note: "RECOVERED",
        content: r#"refresh_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#,
    },
    // ---- Clean: non-secrets that must stay silent ----------------------------
    Case {
        id: "uuid-v4",
        kind: Clean,
        hint: "prefilter",
        note: "",
        content: r#"id = "f47ac10b-58cc-4372-a567-0e02b2c3d479""#,
    },
    Case {
        id: "npm-integrity-hash",
        kind: Clean,
        hint: "prefilter",
        note: "",
        content: r#""integrity": "sha512-XJ8pQ3nKz2vRwT9mYd4fA6bC1eH0gL7sN2oP5qU8wZ""#,
    },
    Case {
        id: "base64-asset-chunk",
        kind: Clean,
        hint: "prefilter",
        note: "",
        content: r#"icon = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ""#,
    },
    Case {
        id: "git-sha-in-comment",
        kind: Clean,
        hint: "prefilter",
        note: "no keyword wakes a rule",
        content: r#"// pinned da39a3ee5e6b4b0d3255bfef95601890afd80709"#,
    },
    // ---- Clean: hash/UUID in a CREDENTIAL-named var — suppressed by the value
    // allowlist (this is the FP class value-based matching would create). ------
    Case {
        id: "md5-cache-key",
        kind: Clean,
        hint: "value-allowlist: md5",
        note: "",
        content: r#"cache_key = "d41d8cd98f00b204e9800998ecf8427e""#,
    },
    Case {
        id: "sha-commit-key",
        kind: Clean,
        hint: "value-allowlist: sha1",
        note: "40-hex in a *_key var",
        content: r#"commit_key = "da39a3ee5e6b4b0d3255bfef95601890afd80709""#,
    },
    Case {
        id: "md5-in-api-key-var",
        kind: Clean,
        hint: "value-allowlist: md5",
        note: "was the old ExpectedFp",
        content: r#"zq_api_key = "d41d8cd98f00b204e9800998ecf8427e""#,
    },
    Case {
        id: "uuid-secret-var",
        kind: Clean,
        hint: "value-allowlist: uuid",
        note: "",
        content: r#"secret_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479""#,
    },
    // ---- Residual: the ACCEPTED cost — a real secret that is itself a hash
    // shape gets allowlisted. Reported, not asserted. ------------------------
    Case {
        id: "hex64-real-secret",
        kind: Residual,
        hint: "value-allowlist: sha256",
        note: "a genuine 64-hex token is allowlisted — real secret we now miss",
        content: r#"api_key = "3f9a2b8c1d7e4650af92bc3d8e1f0a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c""#,
    },
];

fn family_of(hint: &str) -> &str {
    hint.split(&[' ', '-', ':'][..]).next().unwrap_or(hint)
}

#[test]
fn secret_scanner_ground_truth() {
    let mut tp_total = 0;
    let mut tp_caught = 0;
    let mut clean_total = 0;
    let mut clean_kept = 0;
    let mut missed_tps: Vec<&str> = Vec::new();
    let mut noisy: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut fallback: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut residual: Vec<(&str, &str, bool)> = Vec::new();

    println!(
        "\n{:<22} {:<10} {:<9} {:<26} rules",
        "case", "kind", "verdict", "hint"
    );
    println!("{}", "-".repeat(92));

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
                        fallback.push((c.id, ids.clone()));
                        ("Tp", "caught*")
                    }
                } else {
                    missed_tps.push(c.id);
                    ("Tp", "MISS")
                }
            }
            Clean => {
                clean_total += 1;
                if fired {
                    noisy.push((c.id, ids.clone()));
                    ("Clean", "NOISE")
                } else {
                    clean_kept += 1;
                    ("Clean", "silent")
                }
            }
            Residual => {
                residual.push((c.id, c.note, fired));
                ("Residual", if fired { "fires" } else { "missed" })
            }
        };
        println!(
            "{:<22} {:<10} {:<9} {:<26} {}",
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
    if !fallback.is_empty() {
        println!("\nTPs caught only by a fallback rule (structural rule missed):");
        for (id, ids) in &fallback {
            println!("  - {id}  ->  {}", ids.join(", "));
        }
    }
    if !residual.is_empty() {
        println!("\naccepted residual (hash-shaped real secrets allowlisted; not asserted):");
        for (id, note, fires) in &residual {
            println!(
                "  - {id}: {}  ({note})",
                if *fires {
                    "now FIRES (allowlist changed)"
                } else {
                    "missed"
                }
            );
        }
    }

    assert!(missed_tps.is_empty(), "recall regression: {missed_tps:?}");
    assert!(
        noisy.is_empty(),
        "precision regression (a value-allowlist gap or over-broad rule): {noisy:?}"
    );
}

#[test]
fn secret_scanner_guards() {
    // Structural secret: redaction removes it, warn preserves+reports.
    let line = r#"gh = "ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K""#;
    let raw = "ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K";
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
    let (warned, wf) = SCANNER.scrub(line, SecretPolicy::Warn);
    assert_eq!(warned, line, "warn must not alter content");
    assert!(!wf.is_empty(), "warn must still report findings");

    // A RECOVERED inline credential is now genuinely guarded (was a leak before
    // the secretGroup override). Redaction removes just the value.
    let inline = r#"access_token = "Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa""#;
    let (out, f) = SCANNER.scrub(inline, SecretPolicy::Redact);
    assert!(!f.is_empty(), "recovered family must be detected: {inline}");
    assert!(
        !out.contains("Zt9Kx2Lm7Qw3Rf6Yb1Nc4Vd8Hj5GpXa"),
        "redact leaked the value: {out}"
    );
}

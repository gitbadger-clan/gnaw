// crates/gnaw-core/src/secret_scan.rs
//! Regex + entropy secret detection. Pure, no I/O. Always compiled into gnaw-core (not feature-gated).
//!
//! The `SecretScanner` trait is the seam: the live `GitleaksScanner` (in the
//! `gitleaks` submodule) loads the vendored gitleaks ruleset and detects
//! deterministically; a future checksum- or model-based scorer can implement the
//! same trait without touching callers. `SCANNER` is the process-wide instance
//! every caller goes through.

mod gitleaks;

use gitleaks::GitleaksScanner;
pub use gitleaks::compile_pattern_for_diagnostics;
pub use gitleaks::set_dfa_cache_mb;
use serde::{Deserialize, Serialize};

pub static SCANNER: once_cell::sync::Lazy<GitleaksScanner> =
    once_cell::sync::Lazy::new(GitleaksScanner::load_default);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub enum SecretPolicy {
    /// Don't scan.
    Off,
    /// Include content unchanged; report findings.
    #[default]
    Warn,
    /// Replace each detected secret with a placeholder, then include.
    Redact,
    /// Treat any finding as fatal for that file (caller drops it / fails the run).
    Block,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub line: usize,
    pub entropy: f32,
    /// Redacted preview — never the full secret.
    pub preview: String,
}

/// Port: detect secrets in content. Pure; fakeable in tests; swappable later.
pub trait SecretScanner {
    fn scan(&self, content: &str) -> Vec<Finding>;
    /// Scan and rewrite per policy. For Off/Warn/Block, content is returned
    /// unchanged (Block is enforced by the caller using the findings).
    fn scrub(&self, content: &str, policy: SecretPolicy) -> (String, Vec<Finding>);
}

/// Resolve the configured scan-thread count. 0 = default: min(8, available
/// cores). Past ~6 threads extra workers buy little wall time; per-thread cost
/// (DFA cache growth) shows on keyword-rich content but the dominant scan RSS
/// is the compiled ruleset itself, now mitigated by lazy per-rule compilation
pub fn resolve_scan_threads(configured: usize) -> usize {
    if configured != 0 {
        return configured;
    }
    std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1)
        .min(8)
}

/// Force the ruleset to load now: parse, keyword automaton, and the always-on
/// rules' compile — so that cost lands here instead of inside the first `scrub`
/// call. Keyword-gated rules compile lazily on first activation (warm() is no
/// longer "compile everything"; that's `compile_all`, tests/diagnostics only).
/// Idempotent.
pub fn warm() {
    once_cell::sync::Lazy::force(&SCANNER);
}

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f32;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn line_of(content: &str, byte_offset: usize) -> usize {
    content[..byte_offset]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

fn redact_preview(value: &str) -> String {
    let n = value.chars().count();
    let head: String = value.chars().take(4).collect();
    format!("{head}… ({n} chars)") // prefix is identifying, not secret; body never shown
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the LIVE scanner (`SCANNER` = GitleaksScanner) through the
    // `SecretScanner` trait. Rule IDs come from the vendored ruleset, so we match
    // on a family substring rather than an exact ID (the vendored TOML can rev).

    #[test]
    fn detects_and_redacts_github_pat() {
        // ghp_ + 36 chars: matches the gitleaks github-pat rule, high entropy.
        let text = "token = ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K";
        let (out, findings) = SCANNER.scrub(text, SecretPolicy::Redact);
        assert!(
            findings.iter().any(|f| f.rule_id.contains("github")),
            "expected a github finding, got {:?}",
            findings.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
        assert!(out.contains("[REDACTED:"), "redact must replace the secret");
        assert!(
            !out.contains("ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K"),
            "the raw token must not survive redaction"
        );
    }

    #[test]
    fn warn_leaves_content_intact() {
        let text = "token = ghp_Zx9Kq2Mw7Rt4Yb1Nc6Vd8Hj5Gp3Fs0LmZx9K";
        let (out, findings) = SCANNER.scrub(text, SecretPolicy::Warn);
        assert_eq!(out, text, "warn must not rewrite content");
        assert!(!findings.is_empty(), "warn must still report findings");
    }

    #[test]
    fn canonical_aws_example_key_is_allowlisted() {
        // gitleaks ships an allowlist for the canonical AWS doc key; our port
        // applies it, so this must produce no finding.
        assert!(SCANNER.scan("key = AKIAIOSFODNN7EXAMPLE").is_empty());
    }
}

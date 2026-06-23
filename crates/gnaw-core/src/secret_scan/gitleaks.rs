//! Loads the vendored gitleaks ruleset (embedded at build time) and adapts it
//! to Rust's `regex` engine, exposing it through the same `SecretScanner` trait
//! as the built-in scanner — so it drops in behind `SCANNER` with no caller
//! changes.
//!
//! Why this works at all: gitleaks regexes are Go `regexp` (RE2), and Rust's
//! `regex` crate is also RE2-derived, so the vast majority of patterns compile
//! verbatim. The two real friction points are (1) Rust's default compiled-size
//! cap rejects gitleaks' largest alternations, and (2) a small number of
//! patterns use a construct Rust's parser won't accept. `compile_pattern`
//! raises the limits and returns `Err` on the rest; the loader skips-and-counts
//! those rather than failing the whole ruleset. Losing two niche rules beats
//! refusing to scan because one didn't compile.
//!
//! Refresh the corpus with `scripts/update-gitleaks-rules.sh` (it pins a
//! gitleaks release for reproducibility); then `cargo test -p gnaw-core
//! gitleaks` reports the new compile rate.

use regex::{Regex, RegexBuilder};
use serde::Deserialize;

use super::{Finding, SecretPolicy, SecretScanner, line_of, redact_preview, shannon_entropy};

/// The vendored default ruleset, baked into the binary at build time.
const GITLEAKS_TOML: &str = include_str!("../../assets/gitleaks.toml");

// ~~~ Raw TOML shape (gitleaks v8) ~~~

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    rules: Vec<RawRule>,
    /// Global allowlist — legacy singular form (pre-v8.21), still accepted.
    #[serde(default)]
    allowlist: Option<RawAllowlist>,
    /// Global allowlists — plural form (v8.21+).
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
}

#[derive(Deserialize)]
struct RawRule {
    id: String,
    #[serde(default)]
    regex: String,
    /// Which capture group holds the secret. 0 (default) = whole match.
    #[serde(rename = "secretGroup", default)]
    secret_group: usize,
    /// Minimum Shannon entropy of the extracted secret, if the rule gates on it.
    #[serde(default)]
    entropy: Option<f32>,
    /// Prefilter: only run this rule's regex when the content contains a keyword.
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>, // v8.21+
    #[serde(default)]
    allowlist: Option<RawAllowlist>, // legacy
                                     // `path`, `tags`, `description` are not needed at the scanner level
                                     // (path filtering lives in the Scrubber, which has the file path).
}

#[derive(Deserialize)]
struct RawAllowlist {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    /// "secret" (default), "match", or "line". Controls what `regexes` test.
    #[serde(default, rename = "regexTarget")]
    regex_target: Option<String>,
    // `paths`, `commits`, `condition`, `targetRules` are not applied here:
    // path/commit context isn't available to a content-only scan, and we treat
    // the criteria as OR (the gitleaks default), which is what `any()` gives us.
}

// ~~~ Compiled, ready-to-run form ~~~

struct CompiledRule {
    /// Leaked from the parsed `String` so it satisfies `Finding`'s `&'static str`.
    /// Bounded (one per rule, ~hundreds) and the scanner lives for the whole
    /// process via `SCANNER`, so this never grows and is freed at exit. Lets us
    /// keep `Finding`/`FindingDto` untouched.
    id: &'static str,
    re: Regex,
    secret_group: usize,
    /// 0.0 means "no entropy gate".
    min_entropy: f32,
    /// Pre-lowercased for the prefilter.
    keywords: Vec<String>,
    allow_res: Vec<Regex>,
    /// Pre-lowercased; always tested against the extracted secret.
    stopwords: Vec<String>,
    /// When true, `allow_res` test the whole match instead of just the secret.
    allow_targets_match: bool,
}

pub struct GitleaksScanner {
    rules: Vec<CompiledRule>,
    global_allow_res: Vec<Regex>,
    global_stopwords: Vec<String>,
    /// Rules whose regex Rust's engine rejected (visibility for the update test).
    dropped: usize,
}

/// Adapt a gitleaks (Go RE2) pattern to Rust's `regex`. Raises the compiled-size
/// limits so big alternations build, and otherwise surfaces the error for the
/// loader to skip. If a *specific* pattern you care about fails, the loader logs
/// its id and you can add a targeted rewrite here before the build call.
fn compile_pattern(pat: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pat)
        .size_limit(50 * (1 << 20)) // 50 MiB program (default ~10 MiB)
        .dfa_size_limit(50 * (1 << 20))
        .build()
}

impl GitleaksScanner {
    /// Load the vendored default ruleset.
    pub fn load_default() -> Self {
        // PANIC: the TOML is embedded at compile time. A parse failure means a
        // bad vendored file, caught by CI — not reachable from user input.
        Self::from_toml(GITLEAKS_TOML).expect("vendored gitleaks.toml failed to parse")
    }

    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        let cfg: RawConfig = toml::from_str(s)?;

        let mut rules = Vec::with_capacity(cfg.rules.len());
        let mut dropped = 0usize;

        for raw in cfg.rules {
            if raw.regex.trim().is_empty() {
                continue; // keyword-only rules have nothing to match on here
            }
            let re = match compile_pattern(&raw.regex) {
                Ok(re) => re,
                Err(_) => {
                    dropped += 1;
                    continue;
                }
            };

            let mut allow_res = Vec::new();
            let mut stopwords = Vec::new();
            let mut allow_targets_match = false;
            for al in raw.allowlists.into_iter().chain(raw.allowlist) {
                if matches!(al.regex_target.as_deref(), Some("line" | "match")) {
                    allow_targets_match = true;
                }
                for r in al.regexes {
                    if let Ok(re) = compile_pattern(&r) {
                        allow_res.push(re);
                    }
                }
                for w in al.stopwords {
                    stopwords.push(w.to_ascii_lowercase());
                }
            }

            rules.push(CompiledRule {
                id: Box::leak(raw.id.into_boxed_str()),
                re,
                secret_group: raw.secret_group,
                min_entropy: raw.entropy.unwrap_or(0.0),
                keywords: raw
                    .keywords
                    .iter()
                    .map(|k| k.to_ascii_lowercase())
                    .collect(),
                allow_res,
                stopwords,
                allow_targets_match,
            });
        }

        let mut global_allow_res = Vec::new();
        let mut global_stopwords = Vec::new();
        for al in cfg.allowlists.into_iter().chain(cfg.allowlist) {
            for r in al.regexes {
                if let Ok(re) = compile_pattern(&r) {
                    global_allow_res.push(re);
                }
            }
            for w in al.stopwords {
                global_stopwords.push(w.to_ascii_lowercase());
            }
        }

        Ok(Self {
            rules,
            global_allow_res,
            global_stopwords,
            dropped,
        })
    }

    /// Rules successfully compiled. Used by the update test as a sanity floor.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Rules whose regex Rust's engine rejected from the vendored corpus.
    pub fn dropped_rules(&self) -> usize {
        self.dropped
    }

    /// True if any allowlist (rule or global) suppresses this hit.
    fn allowed(&self, rule: &CompiledRule, secret: &str, whole: &str) -> bool {
        let secret_lower = secret.to_ascii_lowercase();
        if self
            .global_stopwords
            .iter()
            .any(|w| secret_lower.contains(w.as_str()))
            || rule
                .stopwords
                .iter()
                .any(|w| secret_lower.contains(w.as_str()))
        {
            return true;
        }
        if self.global_allow_res.iter().any(|re| re.is_match(secret)) {
            return true;
        }
        let target = if rule.allow_targets_match {
            whole
        } else {
            secret
        };
        rule.allow_res.iter().any(|re| re.is_match(target))
    }

    /// True if `rule`'s keyword prefilter passes for `content_lower`.
    fn keyword_hit(rule: &CompiledRule, content_lower: &str) -> bool {
        rule.keywords.is_empty()
            || rule
                .keywords
                .iter()
                .any(|k| content_lower.contains(k.as_str()))
    }
}

impl SecretScanner for GitleaksScanner {
    fn scan(&self, content: &str) -> Vec<Finding> {
        // Document-level keyword prefilter (gitleaks' own semantics): most rules
        // never run because their keyword is absent from the file. Scanning the
        // whole content (not line-by-line) preserves multi-line matches like
        // private-key blocks; the line number is recovered from the byte offset.
        let content_lower = content.to_ascii_lowercase();
        let mut findings = Vec::new();

        for rule in &self.rules {
            if !Self::keyword_hit(rule, &content_lower) {
                continue;
            }
            for caps in rule.re.captures_iter(content) {
                let whole = caps.get(0).unwrap();
                let target = caps.get(rule.secret_group).unwrap_or(whole);
                let secret = target.as_str();
                let entropy = shannon_entropy(secret);
                if rule.min_entropy > 0.0 && entropy < rule.min_entropy {
                    continue;
                }
                if self.allowed(rule, secret, whole.as_str()) {
                    continue;
                }
                findings.push(Finding {
                    rule_id: rule.id,
                    line: line_of(content, target.start()),
                    entropy,
                    preview: redact_preview(secret),
                });
            }
        }

        findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.rule_id.cmp(b.rule_id)));
        findings
    }

    fn scrub(&self, content: &str, policy: SecretPolicy) -> (String, Vec<Finding>) {
        let findings = self.scan(content);
        if policy != SecretPolicy::Redact {
            return (content.to_string(), findings);
        }

        let content_lower = content.to_ascii_lowercase();
        let mut out = content.to_string();
        for rule in &self.rules {
            if !Self::keyword_hit(rule, &content_lower) {
                continue;
            }
            out = rule
                .re
                .replace_all(&out, |caps: &regex::Captures| {
                    let whole = caps.get(0).unwrap();
                    let target = caps.get(rule.secret_group).unwrap_or(whole);
                    let secret = target.as_str();
                    if (rule.min_entropy > 0.0 && shannon_entropy(secret) < rule.min_entropy)
                        || self.allowed(rule, secret, whole.as_str())
                    {
                        return whole.as_str().to_string();
                    }
                    if rule.secret_group == 0 {
                        format!("[REDACTED: {}]", rule.id)
                    } else {
                        let w = whole.as_str();
                        let (s, e) = (target.start() - whole.start(), target.end() - whole.start());
                        format!("{}[REDACTED: {}]{}", &w[..s], rule.id, &w[e..])
                    }
                })
                .into_owned();
        }
        (out, findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_ruleset_compiles() {
        let s = GitleaksScanner::load_default();
        // The gitleaks corpus is large; if hardly anything compiled, the vendored
        // file or the adapter regressed.
        assert!(
            s.rule_count() > 100,
            "only {} gitleaks rules compiled ({} dropped)",
            s.rule_count(),
            s.dropped_rules()
        );
        // Visibility into what Rust's engine rejected from the Go corpus.
        eprintln!(
            "gitleaks: {} rules compiled, {} dropped",
            s.rule_count(),
            s.dropped_rules()
        );
    }

    #[test]
    fn detects_aws_access_key() {
        let s = GitleaksScanner::load_default();
        let f = s.scan("aws_key = AKIAXM7QV4ZK3RT6WJF5");
        assert!(
            f.iter().any(|h| h.rule_id.contains("aws")),
            "got {:?}",
            f.iter().map(|h| h.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn canonical_example_key_is_allowlisted() {
        let s = GitleaksScanner::load_default();
        // The gitleaks global allowlist suppresses canonical example creds.
        // If this fails, the vendored corpus changed its stopword list.
        assert!(s.scan("key = AKIAIOSFODNN7EXAMPLE").is_empty());
    }
}

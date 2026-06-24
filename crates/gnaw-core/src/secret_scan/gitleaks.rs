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
//! those rather than failing the whole ruleset.
//!
//! Performance: the ~360-rule corpus is made tractable by a single shared
//! Aho-Corasick keyword prefilter. gitleaks pairs each rule with keywords that
//! must be present for the rule to fire; instead of testing every rule's
//! keywords against every file (hundreds of substring scans per file), we build
//! ONE case-insensitive automaton over all keywords, run it once per file, and
//! activate only the rules whose keywords actually appear. Rules without
//! keywords are always-on. This also removes the per-file lowercase allocation,
//! since the automaton matches case-insensitively against the original bytes.
//!
//! Refresh the corpus with `cargo xtask update-gitleaks`; then
//! `cargo test -p gnaw-core gitleaks` reports the compile rate.

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
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
    /// `secret_group == 0` — the whole match is the secret. Lets `scan` use the
    /// cheaper `find_iter` (no capture-group tracking) for the common case.
    whole_match: bool,
    /// 0.0 means "no entropy gate".
    min_entropy: f32,
    allow_res: Vec<Regex>,
    /// Pre-lowercased; always tested against the extracted secret.
    stopwords: Vec<String>,
    /// When true, `allow_res` test the whole match instead of just the secret.
    allow_targets_match: bool,
}

pub struct GitleaksScanner {
    rules: Vec<CompiledRule>,
    /// Shared keyword automaton over every rule's keywords (case-insensitive).
    /// `None` only if no rule declares a keyword.
    keyword_ac: Option<AhoCorasick>,
    /// keyword pattern id -> rule indices that declared it.
    keyword_to_rules: Vec<Vec<usize>>,
    /// Rule indices with no keywords: run on every file.
    always_on: Vec<usize>,
    global_allow_res: Vec<Regex>,
    global_stopwords: Vec<String>,
    /// Rules whose regex Rust's engine rejected (visibility for the update test).
    dropped: usize,
}

/// Adapt a gitleaks (Go RE2) pattern to Rust's `regex`. Raises the compiled-size
/// limits so big alternations build, and otherwise surfaces the error for the
/// loader to skip. If a *specific* pattern you care about fails, add a targeted
/// rewrite here before the build call.
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

        // Per-rule outcome of the parallel compile pass. Kept distinct so the
        // sequential assembly reproduces the original drop accounting exactly: an
        // empty regex is a SKIP (keyword-only rule, not a failure), a compile error
        // is a DROP (counted), everything else is ready to install.
        enum Prep {
            Skip,
            Dropped,
            Ready(Prepared),
        }
        struct Prepared {
            id: String,
            re: Regex,
            secret_group: usize,
            min_entropy: f32,
            keywords: Vec<String>,
            allow_res: Vec<Regex>,
            stopwords: Vec<String>,
            allow_targets_match: bool,
        }

        // Compiling the ~360-rule corpus is the dominant startup cost (~2s serial):
        // each rule is an RE2 program plus its allowlist regexes, all independent
        // and pure. Compile in parallel. into_par_iter() preserves input ORDER, so
        // the rule indices the keyword prefilter is built against below are
        // identical to the serial version — findings are unchanged.
        let prepared: Vec<Prep> = cfg
            .rules
            .into_par_iter()
            .map(|raw| {
                if raw.regex.trim().is_empty() {
                    return Prep::Skip; // keyword-only rule: nothing to match on here
                }
                let re = match compile_pattern(&raw.regex) {
                    Ok(re) => re,
                    Err(_) => return Prep::Dropped,
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

                Prep::Ready(Prepared {
                    id: raw.id,
                    re,
                    secret_group: raw.secret_group,
                    min_entropy: raw.entropy.unwrap_or(0.0),
                    keywords: raw.keywords,
                    allow_res,
                    stopwords,
                    allow_targets_match,
                })
            })
            .collect();

        // Sequential assembly: install compiled rules in order, intern keywords into
        // the shared automaton, tally drops. Cheap next to compilation.
        let mut rules = Vec::with_capacity(prepared.len());
        let mut dropped = 0usize;
        let mut kw_ids: HashMap<String, usize> = HashMap::new();
        let mut kw_patterns: Vec<String> = Vec::new();
        let mut keyword_to_rules: Vec<Vec<usize>> = Vec::new();
        let mut always_on: Vec<usize> = Vec::new();

        for prep in prepared {
            let prep = match prep {
                Prep::Skip => continue,
                Prep::Dropped => {
                    dropped += 1;
                    continue;
                }
                Prep::Ready(p) => p,
            };

            let rule_idx = rules.len();
            if prep.keywords.is_empty() {
                always_on.push(rule_idx);
            } else {
                for kw in &prep.keywords {
                    let kw = kw.to_ascii_lowercase();
                    let id = *kw_ids.entry(kw.clone()).or_insert_with(|| {
                        kw_patterns.push(kw);
                        keyword_to_rules.push(Vec::new());
                        kw_patterns.len() - 1
                    });
                    keyword_to_rules[id].push(rule_idx);
                }
            }

            rules.push(CompiledRule {
                id: Box::leak(prep.id.into_boxed_str()),
                whole_match: prep.secret_group == 0,
                re: prep.re,
                secret_group: prep.secret_group,
                min_entropy: prep.min_entropy,
                allow_res: prep.allow_res,
                stopwords: prep.stopwords,
                allow_targets_match: prep.allow_targets_match,
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

        let keyword_ac = if kw_patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&kw_patterns)
                    .expect("aho-corasick build over gitleaks keyword set"),
            )
        };

        Ok(Self {
            rules,
            keyword_ac,
            keyword_to_rules,
            always_on,
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

    /// One automaton pass marks which rules are live for `content`: the
    /// always-on rules plus any rule whose keyword appears. Returns a per-rule
    /// boolean indexed parallel to `self.rules`.
    fn active_rules(&self, content: &str) -> Vec<bool> {
        let mut active = vec![false; self.rules.len()];
        for &r in &self.always_on {
            active[r] = true;
        }
        if let Some(ac) = &self.keyword_ac {
            let mut seen = vec![false; self.keyword_to_rules.len()];
            for m in ac.find_overlapping_iter(content) {
                let pid = m.pattern().as_usize();
                if seen[pid] {
                    continue;
                }
                seen[pid] = true;
                for &r in &self.keyword_to_rules[pid] {
                    active[r] = true;
                }
            }
        }
        active
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
}

impl SecretScanner for GitleaksScanner {
    fn scan(&self, content: &str) -> Vec<Finding> {
        let active = self.active_rules(content);
        let mut findings = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            if !active[i] {
                continue;
            }
            if rule.whole_match {
                // Common case: the whole match is the secret. `find_iter` skips
                // capture-group tracking that `captures_iter` would pay for.
                for m in rule.re.find_iter(content) {
                    let secret = m.as_str();
                    let entropy = shannon_entropy(secret);
                    if rule.min_entropy > 0.0 && entropy < rule.min_entropy {
                        continue;
                    }
                    if self.allowed(rule, secret, secret) {
                        continue;
                    }
                    findings.push(Finding {
                        rule_id: rule.id,
                        line: line_of(content, m.start()),
                        entropy,
                        preview: redact_preview(secret),
                    });
                }
            } else {
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
        }

        findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.rule_id.cmp(b.rule_id)));
        findings
    }

    fn scrub(&self, content: &str, policy: SecretPolicy) -> (String, Vec<Finding>) {
        let findings = self.scan(content);
        if policy != SecretPolicy::Redact {
            return (content.to_string(), findings);
        }

        // Active set computed from the original content; redaction only removes
        // secrets, so no rule that was inactive could become active mid-rewrite.
        let active = self.active_rules(content);
        let mut out = content.to_string();
        for (i, rule) in self.rules.iter().enumerate() {
            if !active[i] {
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
        assert!(
            s.rule_count() > 100,
            "only {} gitleaks rules compiled ({} dropped)",
            s.rule_count(),
            s.dropped_rules()
        );
        eprintln!(
            "gitleaks: {} rules compiled, {} dropped",
            s.rule_count(),
            s.dropped_rules()
        );
    }

    #[test]
    fn detects_aws_access_key() {
        let s = GitleaksScanner::load_default();
        // AKIA + 16 chars from the base32 alphabet [A-Z2-7], high entropy.
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
        assert!(s.scan("key = AKIAIOSFODNN7EXAMPLE").is_empty());
    }
}

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
//! raises the limits and returns `Err` on the rest; a failing rule is
//! skipped-and-counted rather than failing the whole ruleset.
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
//! Memory: rule regexes compile LAZILY, on first activation. The compiled
//! programs — not the DFA caches, not per-scan allocations — are the dominant
//! scan-side RSS (measured ~900 MB for the full corpus pre-unicode(false); see
//! the memscale decomposition), so a rule whose keyword never appears in the
//! scanned content costs only its pattern string. Always-on rules compile
//! eagerly at load: they run on every file, so deferring them would just move
//! their cost into the first file's latency. The keyword automaton is built
//! from the raw TOML strings and needs no compiled regexes. Lazy compilation
//! is invisible to output: same rules, same order, `OnceLock` makes concurrent
//! first-activation race-free (one worker compiles, the rest wait).
//!
//! Refresh the corpus with `cargo xtask update-gitleaks`; then
//! `cargo test -p gnaw-core gitleaks` reports the compile rate (the test
//! force-compiles via `compile_all`, since drops now surface lazily).

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Finding, SecretPolicy, SecretScanner, line_of, redact_preview, shannon_entropy};

/// Process-wide per-thread DFA-cache limit (MB) for the scan ruleset. Set once,
/// before the scanner first compiles ANY pattern — with lazy rule compilation
/// that means before `secret_scan::warm()` (which compiles the always-on set)
/// AND it keeps applying to keyword-gated rules compiled arbitrarily later,
/// because every compile reads it through `dfa_size_limit_bytes`. Later `set`
/// calls are ignored. The scanner is a process singleton, so this is genuinely
/// a process-level knob.
static DFA_LIMIT_MB: OnceLock<usize> = OnceLock::new();
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

/// The compiled regex programs — the megabytes. Everything else on
/// `CompiledRule` is eager metadata (strings, flags): cheap, and needed by the
/// keyword prefilter / assembly before any compile happens.
struct CompiledParts {
    re: Regex,
    allow_res: Vec<Regex>,
}

struct CompiledRule {
    /// Leaked from the parsed `String` so it satisfies `Finding`'s `&'static str`.
    /// Bounded (one per rule, ~hundreds) and the scanner lives for the whole
    /// process via `SCANNER`, so this never grows and is freed at exit. Lets us
    /// keep `Finding`/`FindingDto` untouched.
    id: &'static str,
    /// Raw pattern source for the lazy compile. KBs across the whole ruleset;
    /// the compiled programs are the MBs.
    pattern: String,
    /// Raw rule-allowlist pattern sources, compiled alongside `pattern`.
    allow_patterns: Vec<String>,
    secret_group: usize,
    /// `secret_group == 0` — the whole match is the secret. Lets `scan` use the
    /// cheaper `find_iter` (no capture-group tracking) for the common case.
    whole_match: bool,
    /// 0.0 means "no entropy gate".
    min_entropy: f32,
    /// Pre-lowercased; always tested against the extracted secret.
    stopwords: Vec<String>,
    /// When true, rule-allowlist regexes test the whole match instead of just
    /// the secret.
    allow_targets_match: bool,
    /// gnaw override: allowlist regexes ALWAYS tested against the secret value,
    /// regardless of `allow_targets_match`. Used to suppress hash/UUID-shaped
    /// values on value-targeted rules (see `gnaw_override`). Compiled EAGERLY
    /// at load: five tiny anchored patterns, and eager keeps the builtin
    /// `expect` failing at startup (loudly, in CI) rather than mid-scan on a
    /// rayon worker.
    value_allow_res: Vec<Regex>,
    /// Lazily compiled programs. Inner `None` = the pattern was rejected at
    /// first activation (counted in `GitleaksScanner::dropped`, warned once).
    parts: OnceLock<Option<CompiledParts>>,
}

impl CompiledRule {
    /// The compiled programs, compiling on first call. Concurrent first
    /// activations are safe: `get_or_init` lets one caller compile while the
    /// rest wait, and every caller sees the same result. Rule-allowlist
    /// pattern failures are skipped silently — the same policy the old
    /// load-time `if let Ok` applied.
    fn parts(&self, dropped: &AtomicUsize) -> Option<&CompiledParts> {
        self.parts
            .get_or_init(|| match compile_pattern(&self.pattern) {
                Ok(re) => {
                    log::debug!(target: "gnaw::scan", "lazy-compiled rule {}", self.id);
                    Some(CompiledParts {
                        re,
                        allow_res: self
                            .allow_patterns
                            .iter()
                            .filter_map(|p| compile_pattern(p).ok())
                            .collect(),
                    })
                }
                Err(e) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    log::warn!(
                        target: "gnaw::scan",
                        "rule {} dropped at lazy compile: {e}",
                        self.id
                    );
                    None
                }
            })
            .as_ref()
    }
}

pub struct GitleaksScanner {
    rules: Vec<CompiledRule>,
    /// Shared keyword automaton over every rule's keywords (case-insensitive).
    /// `None` only if no rule declares a keyword. Built from raw TOML strings —
    /// prefiltering needs no compiled regexes.
    keyword_ac: Option<AhoCorasick>,
    /// keyword pattern id -> rule indices that declared it.
    keyword_to_rules: Vec<Vec<usize>>,
    /// Rule indices with no keywords: run on every file. Compiled eagerly at
    /// load — see the module doc.
    always_on: Vec<usize>,
    global_allow_res: Vec<Regex>,
    global_stopwords: Vec<String>,
    /// Rules whose regex Rust's engine rejected. With lazy compilation this
    /// counts drops observed SO FAR (a bad pattern surfaces when its keyword
    /// first fires) — call `compile_all` first for a final count.
    dropped: AtomicUsize,
}

/// Set the scan DFA-cache limit (MB). 0 is a no-op (falls through to env/default),
/// as is any call after the first pattern has already compiled — in practice:
/// set it before `secret_scan::warm()` and it covers the always-on compile there
/// AND every later lazy compile.
pub fn set_dfa_cache_mb(mb: usize) {
    if mb != 0 {
        let _ = DFA_LIMIT_MB.set(mb);
    }
}

/// Resolve the DFA cache size in bytes: explicit setter > `GNAW_DFA_MB` env
/// (kept so the bench harness keeps working) > 32 MB default.
fn dfa_size_limit_bytes() -> usize {
    let mb = DFA_LIMIT_MB
        .get()
        .copied()
        .or_else(|| {
            std::env::var("GNAW_DFA_MB")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
        })
        .filter(|&n| n > 0)
        .unwrap_or(32);
    mb * (1 << 20)
}

/// Adapt a gitleaks (Go RE2) pattern to Rust's `regex`. Raises the compiled-size
/// limits so big alternations build, and otherwise surfaces the error for the
/// caller to skip-and-count. `unicode(false)` matches Go regexp semantics
/// (gitleaks' native engine: `\w`, `(?i)` are ASCII there) and avoids compiling
/// Unicode case-folding tables into every big `(?i)` alternation. If a
/// *specific* pattern you care about fails, add a targeted rewrite here before
/// the build call.
fn compile_pattern(pat: &str) -> Result<Regex, regex::Error> {
    let build = |unicode: bool| {
        RegexBuilder::new(pat)
            .unicode(unicode)
            .size_limit(50 * (1 << 20))
            .dfa_size_limit(dfa_size_limit_bytes())
            .build()
    };
    // ASCII-first (Go-regexp semantics, and MUCH smaller programs for the big
    // (?i) alternations). A handful of patterns use constructs that only parse
    // in Unicode mode (\x{...} > 0x7F, etc.) — fall back rather than drop them.
    build(false).or_else(|_| build(true))
}

/// Diagnostics only (xtask rule-memory): the exact builder settings the
/// scanner uses, so measured sizes describe what actually ships.
#[doc(hidden)]
pub fn compile_pattern_for_diagnostics(pat: &str) -> Result<Regex, regex::Error> {
    compile_pattern(pat)
}

/// True if `haystack` contains `needle` case-insensitively (ASCII). `needle`
/// MUST already be ASCII-lowercase (stopwords are lowered at load). Allocation-free:
/// slides a window and compares with eq_ignore_ascii_case instead of lowercasing
/// the whole haystack per call.
fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() {
        return true;
    }
    if n.len() > h.len() {
        return false;
    }
    // Anchor on the first byte (case-folded) to skip most windows cheaply.
    let n0 = n[0];
    h.windows(n.len())
        .any(|w| w[0].eq_ignore_ascii_case(&n0) && w.eq_ignore_ascii_case(n))
}

/// Rules compiled eagerly at load alongside the always-on set. Criteria: their
/// keywords are near-universal in real code (they'd lazy-compile on the first
/// few files anyway, so eager costs ~nothing on real repos) and/or they're
/// expensive enough that a mid-scan first compile is a visible latency spike.
/// Curated from `cargo run -p xtask --bin rule-memory` — revisit when the
/// vendored ruleset revs.
const HOT_RULES: &[&str] = &["generic-api-key", "jwt", "private-key"];

/// gnaw-specific overrides layered on top of the vendored gitleaks rules, so
/// they survive `cargo xtask update-gitleaks` (they live in code, not the TOML).
///
/// generic-api-key ships with no secretGroup, so gitleaks treats the WHOLE match
/// as the secret and its ~1.4k stopwords suppress by variable NAME — silently
/// dropping access_token / auth_token / password / client_secret / … (gitleaks
/// itself misses these). We set secretGroup=1 so stopwords test the VALUE, which
/// recovers those families. The cost is that a high-entropy hash in a
/// credential-named var now looks like a secret; `value_allow_res` suppresses
/// the hash/UUID shapes that cause it. Accepted residual: a real secret that is
/// itself pure-hex-of-hash-length or UUID-shaped gets allowlisted.
struct RuleOverride {
    secret_group: Option<usize>,
    /// Replaces the vendored regex entirely (raw source — compiles lazily like
    /// any pattern, so an override participates in the memory story unchanged).
    pattern: Option<&'static str>,
    value_allow_res: Vec<Regex>,
}

fn gnaw_override(id: &str) -> Option<RuleOverride> {
    match id {
        "generic-api-key" => {
            // Anchored to the whole value: a token that merely CONTAINS hex isn't hit.
            let value_allow_res = [
                r"^[a-fA-F0-9]{32}$", // md5
                r"^[a-fA-F0-9]{40}$", // sha1 / git sha
                r"^[a-fA-F0-9]{64}$", // sha256
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", // uuid
                r"^sha(?:256|512)-[A-Za-z0-9+/]+={0,2}$", // subresource-integrity hash
            ]
            .iter()
            .map(|p| compile_pattern(p).expect("builtin gnaw value-allowlist regex"))
            .collect();
            Some(RuleOverride {
                secret_group: Some(1),
                pattern: None,
                value_allow_res,
            })
        }
        // The vendored pattern closes on the bare `KEY----` suffix, so a short/
        // truncated PEM stub lazily extends and CONSUMES the next block's BEGIN
        // marker — a stub above a real key shadows it (detection bypass), and
        // doc placeholders match at all. Adopted from the closed gitleaks PR
        // #1594 (rgmz; in production in LeakTK's patterns): requires a full END
        // marker to close and >=2 base64 runs of 64 chars, so placeholders
        // can't match and a match can't swallow a BEGIN. Residual: a stub
        // directly above a real key attributes the finding to the stub's line
        // (the key content is still inside the match). Drop this override if
        // upstream merges an equivalent.
        "private-key" => Some(RuleOverride {
            secret_group: None,
            // {1}, not the PR's {2}: an Ed25519 PKCS#8 body is a SINGLE 64-char
            // base64 line, which {2} misses (confirmed live via
            // `openssl genpkey -algorithm ed25519 | gnaw`). Placeholders have
            // ZERO 64-char runs, so {1} still suppresses them, and the full-END
            // close still prevents the BEGIN-swallowing shadowing.
            pattern: Some(
                r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:[a-z0-9/+]{64}[\s\S]*?){1}-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----",
            ),
            value_allow_res: Vec::new(),
        }),
        _ => None,
    }
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

        // Assembly: install rules in order (patterns raw, uncompiled), intern
        // keywords into the shared automaton. Rule regexes compile lazily on
        // first activation; only the always-on set compiles here, at the end.
        // Empty-regex rules are keyword-only entries: skipped, same as before
        // (a skip, not a drop).
        let mut rules = Vec::with_capacity(cfg.rules.len());
        let mut kw_ids: HashMap<String, usize> = HashMap::new();
        let mut kw_patterns: Vec<String> = Vec::new();
        let mut keyword_to_rules: Vec<Vec<usize>> = Vec::new();
        let mut always_on: Vec<usize> = Vec::new();

        for raw in cfg.rules {
            if raw.regex.trim().is_empty() {
                continue; // keyword-only rule: nothing to match on here
            }

            let mut allow_patterns = Vec::new();
            let mut stopwords = Vec::new();
            let mut allow_targets_match = false;
            for al in raw.allowlists.into_iter().chain(raw.allowlist) {
                if matches!(al.regex_target.as_deref(), Some("line" | "match")) {
                    allow_targets_match = true;
                }
                for r in al.regexes {
                    allow_patterns.push(r);
                }
                for w in al.stopwords {
                    stopwords.push(w.to_ascii_lowercase());
                }
            }

            let rule_idx = rules.len();
            if raw.keywords.is_empty() {
                always_on.push(rule_idx);
            } else {
                for kw in &raw.keywords {
                    let kw = kw.to_ascii_lowercase();
                    let id = *kw_ids.entry(kw.clone()).or_insert_with(|| {
                        kw_patterns.push(kw);
                        keyword_to_rules.push(Vec::new());
                        kw_patterns.len() - 1
                    });
                    keyword_to_rules[id].push(rule_idx);
                }
            }

            let ov = gnaw_override(&raw.id);
            let secret_group = ov
                .as_ref()
                .and_then(|o| o.secret_group)
                .unwrap_or(raw.secret_group);
            let pattern = ov
                .as_ref()
                .and_then(|o| o.pattern)
                .map(str::to_owned)
                .unwrap_or(raw.regex);
            let value_allow_res = ov.map(|o| o.value_allow_res).unwrap_or_default();

            rules.push(CompiledRule {
                id: Box::leak(raw.id.into_boxed_str()),
                whole_match: secret_group == 0,
                pattern,
                allow_patterns,
                secret_group,
                min_entropy: raw.entropy.unwrap_or(0.0),
                stopwords,
                allow_targets_match,
                value_allow_res,
                parts: OnceLock::new(),
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

        let scanner = Self {
            rules,
            keyword_ac,
            keyword_to_rules,
            always_on,
            global_allow_res,
            global_stopwords,
            dropped: AtomicUsize::new(0),
        };

        // Eager set: always-on rules (they run on every file — deferring them
        // would just move their compile into the first file's scan latency)
        // plus the curated HOT_RULES (keywords so ubiquitous in real code that
        // they'd lazy-compile within the first files anyway — eager trades
        // ~nothing in memory for no mid-scan compile spike). Everything else
        // waits for its keyword to actually appear in scanned content.
        let always: std::collections::HashSet<usize> = scanner.always_on.iter().copied().collect();
        let eager: Vec<usize> = scanner
            .rules
            .iter()
            .enumerate()
            .filter(|(i, r)| always.contains(i) || HOT_RULES.contains(&r.id))
            .map(|(i, _)| i)
            .collect();
        eager.par_iter().for_each(|&i| {
            let _ = scanner.rules[i].parts(&scanner.dropped);
        });

        Ok(scanner)
    }

    /// Rules installed from the ruleset (compilation may still be pending for
    /// keyword-gated rules). Used by the update test as a sanity floor,
    /// together with `compile_all` + `dropped_rules`.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Rules whose regex Rust's engine rejected — the count observed SO FAR.
    /// With lazy compilation a bad pattern only surfaces when its keyword first
    /// fires; call `compile_all` first for a final count.
    pub fn dropped_rules(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Force-compile every rule. For the update test and diagnostics ONLY — it
    /// defeats the lazy-compile memory win for this process. After this,
    /// `dropped_rules` is final rather than so-far.
    pub fn compile_all(&self) {
        self.rules.par_iter().for_each(|r| {
            let _ = r.parts(&self.dropped);
        });
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

    /// True if any allowlist (rule or global) suppresses this hit. `parts` is
    /// the rule's compiled programs (already resolved by the caller — every
    /// caller has them in hand, since a finding implies the rule compiled).
    fn allowed(
        &self,
        rule: &CompiledRule,
        parts: &CompiledParts,
        secret: &str,
        whole: &str,
    ) -> bool {
        // Stopwords are pre-lowered at load. Check case-insensitive containment
        // WITHOUT allocating a lowercased copy of the secret (per-match String
        // alloc × 222 rules × N files was the bulk of the scan's page faults).
        let gate = if self
            .global_stopwords
            .iter()
            .any(|w| contains_ascii_ci(secret, w))
        {
            "global-stopword"
        } else if rule.stopwords.iter().any(|w| contains_ascii_ci(secret, w)) {
            "rule-stopword"
        } else if self.global_allow_res.iter().any(|re| re.is_match(secret)) {
            "global-allowlist"
        } else if rule.value_allow_res.iter().any(|re| re.is_match(secret)) {
            // gnaw override: value-shape suppressors (hash/UUID/SRI). ALWAYS
            // tested against the secret VALUE, regardless of allow_targets_match.
            "value-shape"
        } else {
            let target = if rule.allow_targets_match {
                whole
            } else {
                secret
            };
            if parts.allow_res.iter().any(|re| re.is_match(target)) {
                "rule-allowlist"
            } else {
                return false;
            }
        };
        // Preview only — a suppressed candidate can still be a real secret;
        // never put the raw value in the log stream.
        log::debug!(
            target: "gnaw::scan::suppress",
            "suppressed [{}] by {gate}: {}",
            rule.id,
            redact_preview(secret)
        );
        true
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
            // Lazy compile on first activation; a rejected pattern is counted
            // and the rule is skipped from then on.
            let Some(parts) = rule.parts(&self.dropped) else {
                continue;
            };
            if rule.whole_match {
                // Whole match is the secret: find_iter (lazy-DFA), no capture tracking.
                for m in parts.re.find_iter(content) {
                    let secret = m.as_str();
                    let entropy = shannon_entropy(secret);
                    if rule.min_entropy > 0.0 && entropy < rule.min_entropy {
                        log::debug!(
                            target: "gnaw::scan::suppress",
                            "suppressed [{}] by entropy {entropy:.2} < {:.1}: {}",
                            rule.id, rule.min_entropy, redact_preview(secret)
                        );
                        continue;
                    }
                    if self.allowed(rule, parts, secret, secret) {
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
                // Capture-group secret. Locate matches with the fast find_iter
                // engine, then resolve the group per-match. Using captures_iter
                // here drives the capture-tracking engine over the WHOLE file,
                // which makes the huge generic-api-key pattern (secretGroup=1) take
                // tens of seconds on large inputs. captures_read_at with the full
                // `content` keeps anchor/boundary context (\b, ^, $) correct.
                let mut locs = parts.re.capture_locations();
                for m in parts.re.find_iter(content) {
                    if parts
                        .re
                        .captures_read_at(&mut locs, content, m.start())
                        .is_none()
                    {
                        continue;
                    }
                    let (gs, ge) = locs.get(rule.secret_group).unwrap_or((m.start(), m.end()));
                    let secret = &content[gs..ge];
                    let entropy = shannon_entropy(secret);
                    if rule.min_entropy > 0.0 && entropy < rule.min_entropy {
                        continue;
                    }
                    if self.allowed(rule, parts, secret, m.as_str()) {
                        continue;
                    }
                    findings.push(Finding {
                        rule_id: rule.id,
                        line: line_of(content, gs),
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
        // Every active rule that matters is already compiled by the scan()
        // above; parts() here just fetches the cached programs.
        let active = self.active_rules(content);
        let mut out = content.to_string();
        for (i, rule) in self.rules.iter().enumerate() {
            if !active[i] {
                continue;
            }
            let Some(parts) = rule.parts(&self.dropped) else {
                continue;
            };
            out = parts
                .re
                .replace_all(&out, |caps: &regex::Captures| {
                    let whole = caps.get(0).unwrap();
                    let target = caps.get(rule.secret_group).unwrap_or(whole);
                    let secret = target.as_str();
                    if (rule.min_entropy > 0.0 && shannon_entropy(secret) < rule.min_entropy)
                        || self.allowed(rule, parts, secret, whole.as_str())
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
        // Lazy compilation: force everything so the drop count is final, then
        // assert on rules that actually COMPILED, not just installed.
        s.compile_all();
        let compiled = s.rule_count() - s.dropped_rules();
        assert!(
            compiled > 100,
            "only {compiled} gitleaks rules compiled ({} dropped)",
            s.dropped_rules()
        );
        eprintln!(
            "gitleaks: {} rules installed, {compiled} compiled, {} dropped",
            s.rule_count(),
            s.dropped_rules()
        );
    }

    #[test]
    fn detects_aws_access_key() {
        let s = GitleaksScanner::load_default();
        // AKIA + 16 chars from the base32 alphabet [A-Z2-7], high entropy.
        // Also exercises the lazy path: the aws rule is keyword-gated and
        // compiles on this first activation.
        let f = s.scan("aws_key = AKIAXM7QV4ZK3RT6WJF5");
        assert!(
            f.iter().any(|h| h.rule_id.contains("aws")),
            "got {:?}",
            f.iter().map(|h| h.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn lazy_compile_is_stable_across_scans() {
        // Second scan of keyword-waking content must go through the cached
        // programs and produce identical findings — compilation timing must be
        // invisible to output.
        let s = GitleaksScanner::load_default();
        let content = "aws_key = AKIAXM7QV4ZK3RT6WJF5";
        let first = s.scan(content);
        let second = s.scan(content);
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.rule_id, b.rule_id);
            assert_eq!(a.line, b.line);
        }
    }

    #[test]
    fn bad_pattern_drops_without_panic() {
        // A rule whose regex Rust rejects must be counted and skipped at first
        // activation — never a panic, never a finding.
        let toml = r#"
            [[rules]]
            id = "bad-backref"
            regex = '(a)\1'
            keywords = ["zzzmagic"]
        "#;
        let s = GitleaksScanner::from_toml(toml).expect("parse");
        assert_eq!(s.rule_count(), 1);
        assert_eq!(
            s.dropped_rules(),
            0,
            "keyword-gated: no compile before activation"
        );
        assert!(s.scan("zzzmagic aa aa").is_empty()); // wakes it → drops it
        assert_eq!(s.dropped_rules(), 1);
    }

    #[test]
    fn canonical_example_key_is_allowlisted() {
        let s = GitleaksScanner::load_default();
        assert!(s.scan("key = AKIAIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn report_dropped_rules() {
        // Diagnostic (not an assertion): the loader counts drops but doesn't name
        // them. Run with --nocapture to see which rules Rust's regex rejects.
        let cfg: RawConfig = toml::from_str(GITLEAKS_TOML).expect("parse");
        let dropped: Vec<_> = cfg
            .rules
            .into_iter()
            .filter(|r| !r.regex.trim().is_empty() && compile_pattern(&r.regex).is_err())
            .map(|r| r.id)
            .collect();
        eprintln!("DROPPED {} rules: {dropped:#?}", dropped.len());
    }
    /// A plausible full-length PEM body: >=2 lines of 64 base64 chars.
    fn dummy_pem(kind: &str) -> String {
        let l1 = "MIIEpAIBAAKCAQEA7vQmXhZk3tR9nWq2LmYc5xJd8fKp0sHg4uNa6bTe1iVw9zoQ";
        let l2 = "kYr3mCx7pDf2sLn8vBt4wGh6jNq1eZa5oXu9iMc0dRy2lKs7fTb3nVp8qWg4hEj6";
        format!("-----BEGIN {kind} PRIVATE KEY-----\n{l1}\n{l2}\n-----END {kind} PRIVATE KEY-----")
    }

    #[test]
    fn private_key_detects_real_key() {
        let s = GitleaksScanner::load_default();
        let f = s.scan(&dummy_pem("RSA"));
        assert!(f.iter().any(|h| h.rule_id == "private-key"), "got {f:?}");
    }

    #[test]
    fn private_key_ignores_truncated_placeholder() {
        let s = GitleaksScanner::load_default();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nKh9NV...\n-----END RSA PRIVATE KEY-----";
        assert!(s.scan(text).iter().all(|h| h.rule_id != "private-key"));
    }

    #[test]
    fn private_key_ignores_two_doc_placeholders() {
        // The env-var-docs shape: two truncated blocks in sequence. Under the
        // vendored pattern the first block's lazy tail consumed the second's
        // BEGIN marker; under the override neither matches (no base64 runs).
        let s = GitleaksScanner::load_default();
        let text = concat!(
            "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\n...\nKh9NV...\n...\n",
            "-----END DSA PRIVATE KEY-----\"\n\n",
            "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\\nKh9NV...\\n-----END DSA PRIVATE KEY-----\\n\"",
        );
        assert!(s.scan(text).iter().all(|h| h.rule_id != "private-key"));
    }

    #[test]
    fn private_key_stub_does_not_shadow_real_key() {
        // The bypass the override exists to close: a stub above a real key must
        // not prevent detection. Residual (asserted): the match starts at the
        // stub, so the finding's line attributes there — but exactly one
        // private-key finding exists and the key content is inside it.
        let s = GitleaksScanner::load_default();
        let text = format!(
            "-----BEGIN RSA PRIVATE KEY-----\nstub...\n-----END RSA PRIVATE KEY-----\n{}",
            dummy_pem("EC")
        );
        let hits: Vec<_> = s
            .scan(&text)
            .into_iter()
            .filter(|h| h.rule_id == "private-key")
            .collect();
        assert_eq!(hits.len(), 1, "real key must be detected despite the stub");
    }
}

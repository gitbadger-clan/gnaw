//! Secret-scan stage. Runs before chunking, scans whole-file (or whole-diff)
//! content, and—per policy—scrubs it. Collects findings independent of the
//! budgeter, so a finding survives even if its file's chunk is later dropped.
//!
//! This is where the secret scan lives now; `extract_raw_file` no longer scans
//! (it yields genuinely raw content, as its name claims). `Off` is a fast
//! passthrough so the no-scan path costs nothing.
//!
//! Only `Redact` rewrites content. `Warn` and `Block` scan for findings but
//! leave the bytes untouched, so they MUST NOT clone the file body — scanning
//! takes `&str` and the original text is moved straight back. Cloning here
//! (the old behavior) duplicated the whole codebase on every default run,
//! since `warn` is the default policy.
//!
//! Files are scanned in parallel (rayon): each item is independent and the scan
//! is CPU-bound. Determinism is preserved because `into_par_iter().map().collect()`
//! keeps input order, and each item collects its OWN findings (no shared Vec),
//! which are flattened back in item order.

use gnaw_core::configuration::GnawConfig;
use gnaw_core::pipeline::{FindingDto, RawContent, RawItem, Scrubber};
use gnaw_core::secret_scan::{SCANNER, SecretPolicy, SecretScanner};
use rayon::prelude::*;

pub struct SecretScrubber {
    policy: SecretPolicy,
    allow_paths: Vec<String>,
}

impl SecretScrubber {
    pub fn new(config: &GnawConfig) -> Self {
        Self {
            policy: config.secret_scan,
            allow_paths: config.secret_scan_allow_paths.clone(),
        }
    }

    /// Scan `text`, appending findings tagged with `path` to `out`. Returns
    /// `Some(rewritten)` ONLY when the policy redacts; `None` means "keep the
    /// original" — the hot path for the default `warn`, where we must not clone
    /// the file body. `out` is the item's own buffer (not shared), so this is
    /// safe to call from a rayon worker.
    fn scan_field(&self, path: &str, text: &str, out: &mut Vec<FindingDto>) -> Option<String> {
        if self.policy == SecretPolicy::Redact {
            let (scrubbed, found) = SCANNER.scrub(text, SecretPolicy::Redact);
            for f in &found {
                out.push(FindingDto::from_core(path.to_string(), f));
            }
            Some(scrubbed)
        } else {
            for f in &SCANNER.scan(text) {
                out.push(FindingDto::from_core(path.to_string(), f));
            }
            None
        }
    }

    /// Scrub one item, returning the (possibly rewritten) item and ITS OWN
    /// findings. Pure per-item work — no shared state — so it runs on any thread.
    fn scrub_item(&self, item: RawItem) -> (RawItem, Vec<FindingDto>) {
        if path_is_allowlisted(&item.path, &self.allow_paths) {
            return (item, Vec::new());
        }

        let mut findings = Vec::new();
        let content = match item.content {
            RawContent::Text { text } => match self.scan_field(&item.path, &text, &mut findings) {
                Some(scrubbed) => RawContent::Text { text: scrubbed },
                None => RawContent::Text { text }, // moved back — no clone
            },
            RawContent::Changed {
                after,
                before,
                patch,
            } => {
                let after = self
                    .scan_field(&item.path, &after, &mut findings)
                    .unwrap_or(after);
                let before =
                    before.map(|b| self.scan_field(&item.path, &b, &mut findings).unwrap_or(b));
                let patch =
                    patch.map(|p| self.scan_field(&item.path, &p, &mut findings).unwrap_or(p));
                RawContent::Changed {
                    after,
                    before,
                    patch,
                }
            }
            // Binary/omitted: nothing to scan.
            RawContent::Omitted => RawContent::Omitted,
        };

        // Dedup this item's findings by (rule_id, line) — diff fields re-surface
        // the same secret across before/after/patch.
        dedup_findings(&mut findings);

        (RawItem { content, ..item }, findings)
    }
}

impl Scrubber for SecretScrubber {
    fn scrub(&self, items: Vec<RawItem>) -> (Vec<RawItem>, Vec<FindingDto>) {
        if self.policy == SecretPolicy::Off {
            return (items, Vec::new());
        }
        // Parallel per-item scan; `collect` into a Vec preserves input order, so
        // both the items and the flattened findings stay deterministic.
        let per_item: Vec<(RawItem, Vec<FindingDto>)> = items
            .into_par_iter()
            .map(|item| self.scrub_item(item))
            .collect();

        let mut scrubbed_items = Vec::with_capacity(per_item.len());
        let mut findings = Vec::new();
        for (item, mut item_findings) in per_item {
            scrubbed_items.push(item);
            findings.append(&mut item_findings);
        }

        (scrubbed_items, findings)
    }
}

/// Dedup a single item's findings by (rule_id, line), keeping first occurrence.
/// In place, order-preserving.
fn dedup_findings(findings: &mut Vec<FindingDto>) {
    let mut seen = std::collections::HashSet::new();
    let mut write = 0;
    for read in 0..findings.len() {
        let key = (findings[read].rule_id.clone(), findings[read].line);
        if seen.insert(key) {
            findings.swap(write, read);
            write += 1;
        }
    }
    findings.truncate(write);
}

/// Same allowlist check the legacy path used — substring match, with a builtin
/// default set when the config list is empty. Lifted from path.rs so the
/// Scrubber owns its own policy logic.
fn path_is_allowlisted(path: &str, allow_paths: &[String]) -> bool {
    const DEFAULTS: &[&str] = &[
        "/tests/",
        "/test/",
        "/fixtures/",
        "/testdata/",
        "/__tests__/",
        "_test.",
    ];
    if allow_paths.is_empty() {
        DEFAULTS.iter().any(|frag| path.contains(frag))
    } else {
        allow_paths.iter().any(|frag| path.contains(frag.as_str()))
    }
}

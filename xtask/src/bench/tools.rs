//! The competitor table for `bench-compare`. This is the single place where
//! "what is fair" is encoded: how each tool is invoked so it does the SAME work
//! as gnaw, and the asterisks for where it can't. Every field here exists
//! because a specific confound was found during benchmarking:
//!
//! - `tokenized_cmd` forces token-mode where a tool byte-counts by default
//!   (yek's `--tokens` — without it, yek does a `wc` and looks 10x faster).
//! - `encoding` is pinned to o200k everywhere it can be, so "total tokens" is
//!   comparable and not just measuring tokenizer choice.
//! - `node_overhead` marks tools that run under Node (repomix, repomix-rs), so
//!   their time AND peak-RSS carry a runtime tax native tools don't pay. This
//!   is disclosed, not hidden — users really do pay it via `npx`.
//! - `sink`/`quiet` normalize output so we time extraction, not terminal render
//!   or clipboard.
//!
//! Versions are PINNED and flow into the methodology report. Unpinned = a
//! benchmark that silently drifts when upstream releases. Confirm each version
//! and flag surface against the installed tool before trusting a run
//! (`<tool> --version`, `<tool> --help`) — CLI surfaces churn.

use std::path::Path;

/// How a tool is provisioned. `bench-setup` reads this; `bench-compare` assumes
/// setup already ran and only resolves/records versions.
#[derive(Clone, Copy)]
pub enum Provision {
    /// crates.io, pinned. Installed into target/bench-tools (not global ~/.cargo).
    Cargo {
        crate_name: &'static str,
        version: &'static str,
    },
    /// Unreleased Rust: git repo at a pinned rev. Note "built from <repo>@<rev>"
    /// in the report — it's reproducible but not a released version users run.
    CargoGit {
        repo: &'static str,
        rev: &'static str,
    },
    /// npm-distributed; run via `npx <spec>`. The spec IS the pinning — no
    /// install step. Carries Node startup in every measured run.
    Npx { spec: &'static str },
    /// gnaw itself: built from the local workspace at --release. The version
    /// under test, not an installed one.
    LocalBuild,
}

/// Which comparison group a tool belongs in. NEVER mix these in one ranking:
/// tokenized vs byte-counted are different work.
#[derive(Clone, Copy, PartialEq)]
pub enum Group {
    /// Real BPE tokenization (o200k where possible). gnaw, code2prompt,
    /// repomix-rs, Node repomix.
    Tokenized,
    /// Byte/char counting only. A tool lands here if it CANNOT be forced to
    /// tokenize with a comparable encoding.
    ByteCount,
}

pub struct Tool {
    pub name: &'static str,
    pub provision: Provision,
    pub group: Group,
    /// True if the tool runs under Node → time and peak-RSS include runtime
    /// baseline. Surfaced as an asterisk in the report.
    pub node_overhead: bool,
    /// Builds the argv for a normalized run against `repo`, writing to `sink`.
    /// `bin` is the resolved executable (from target/bench-tools/bin or PATH);
    /// for Npx tools it's "npx" and the spec is prepended in the builder.
    pub build_cmd: fn(bin: &str, repo: &Path, sink: &Path) -> Vec<String>,
    /// After a run, counts files the tool actually emitted, by parsing its
    /// output at `sink`. This is the completeness check that separates "faster"
    /// from "did less" — the whole reason the yek result became trustworthy.
    /// Returns None if the tool's output format isn't parseable for counts.
    pub count_files: fn(sink: &Path) -> Option<usize>,
}

/// The field. Order is report order. Keep gnaw first.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "gnaw",
            provision: Provision::LocalBuild,
            group: Group::Tokenized,
            node_overhead: false,
            build_cmd: |bin, repo, sink| {
                // --secret-scan off = the extraction-speed number (fair vs tools
                // that don't scan). The WITH-scanning number is a separate run;
                // don't fold the scanner tax into the head-to-head speed claim.
                // o200k matches the other tiktoken tools.
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--encoding".into(),
                    "o200k".into(),
                    "--secret-scan".into(),
                    "off".into(),
                    "--quiet".into(),
                    "-O".into(),
                    sink.display().to_string(),
                ]
            },
            count_files: |sink| {
                count_matches(sink, |l| {
                    // gnaw XML: one structural `</file>` per file, on its own line.
                    // Anchored so a `</file>` inside bundled content doesn't count.
                    l.trim() == "</file>"
                })
            },
        },
        Tool {
            name: "code2prompt",
            provision: Provision::Cargo {
                crate_name: "code2prompt",
                version: "VERIFY",
            },
            group: Group::Tokenized,
            node_overhead: false,
            // Fairest comparison: gnaw's fork ancestor, native, tiktoken.
            // VERIFY its flags: output-to-file/stdout, quiet, and the encoding
            // flag (must be pinnable to o200k). Fill once `code2prompt --help`
            // is confirmed — do NOT guess, a wrong flag benchmarks a degraded
            // mode.
            build_cmd: |_bin, _repo, _sink| {
                vec!["TODO: code2prompt argv — confirm via --help".into()]
            },
            count_files: |_sink| None, // fill once output format confirmed
        },
        Tool {
            name: "yek",
            // TWO repos exist (bodo-run vs mohsen1). Resolve the maintained one
            // before pinning; they have separate release streams.
            provision: Provision::CargoGit {
                repo: "mohsen1/yek",
                rev: "VERIFY",
            },
            group: Group::Tokenized,
            node_overhead: false,
            build_cmd: |bin, repo, _sink| {
                // --tokens is MANDATORY. Without it yek byte-counts and the
                // comparison is meaningless. Budget set larger than the repo so
                // it processes everything (matching gnaw's whole-repo run), not
                // a budget-clipped subset. yek streams to a temp file and prints
                // the path; sink is handled by reading that path post-run.
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--tokens".into(),
                    "16000k".into(),
                ]
            },
            count_files: |_sink| None, // yek: count `^>>>> ` headers in its temp output
        },
        Tool {
            name: "repomix-rs",
            provision: Provision::Npx {
                spec: "repomix-rs@VERIFY",
            },
            group: Group::Tokenized,
            node_overhead: true, // Rust core but npm-distributed → Node startup
            // Claims o200k_base — match it so tokens are comparable. VERIFY its
            // flags (stdout/output, quiet) and that compression is OFF for a
            // raw-vs-raw compare (compression = different work).
            build_cmd: |_bin, _repo, _sink| {
                vec!["TODO: npx repomix-rs argv — confirm via --help".into()]
            },
            count_files: |_sink| None,
        },
        Tool {
            name: "repomix",
            provision: Provision::Npx {
                spec: "repomix@VERIFY",
            },
            group: Group::Tokenized,
            node_overhead: true,
            // The reference baseline everyone knows. Node startup asterisk.
            // --stdout to sink, --quiet, and compression OFF (default `repomix`
            // does NOT compress unless --compress, so default is fine for raw).
            build_cmd: |_bin, repo, sink| {
                vec![
                    "npx".into(),
                    "repomix@VERIFY".into(),
                    repo.display().to_string(),
                    "--stdout".into(),
                    "--quiet".into(),
                    // redirect handled by caller; repomix --stdout writes stdout
                    "--output".into(),
                    sink.display().to_string(),
                ]
            },
            count_files: |_sink| None, // repomix XML: count `<file path=` structural tags
        },
        // Go repomix (StevenACoffman) deliberately OMITTED from the primary
        // table: needs the Go toolchain (won't build in the Rust bench image),
        // and its value axis barely overlaps. If wanted, add as a "completeness"
        // tier data point, not a headline comparison.
    ]
}

/// Count lines in the sink matching a predicate. Small files; read to string.
fn count_matches(sink: &Path, pred: fn(&str) -> bool) -> Option<usize> {
    let text = std::fs::read_to_string(sink).ok()?;
    Some(text.lines().filter(|l| pred(l)).count())
}

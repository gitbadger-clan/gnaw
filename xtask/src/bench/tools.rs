//! The competitor table for `bench-compare`. This is the single place where
//! "what is fair" is encoded: how each tool is invoked so it does the SAME work
//! as gnaw, and the asterisks for where it can't. Every field exists because a
//! specific confound was found during benchmarking:
//!
//! - `--tokens` forces token-mode where a tool byte-counts by default (yek —
//!   without it, yek does a `wc` and looks 10x faster).
//! - encoding pinned to o200k everywhere it can be. Where a tool CANNOT do o200k
//!   (code2prompt tops out at cl100k), `token_comparable = false` so the report
//!   knows its token TOTAL isn't rankable against the o200k tools — though its
//!   time/memory/file-count still are.
//! - `node_overhead` marks tools that run under Node (repomix, repomix-rs): time
//!   AND peak-RSS carry a runtime tax native tools don't pay. Disclosed.
//! - every tool writes to the harness-assigned `sink` so the completeness count
//!   reads the file WE control (yek needed --output-dir/--output-name for this).
//!
//! Versions are PINNED and flow into the methodology report. Confirm each
//! version and flag surface against the installed tool (`<tool> --version`).

use std::path::Path;

#[derive(Clone, Copy)]
pub enum Provision {
    Cargo {
        crate_name: &'static str,
        version: &'static str,
    },
    CargoGit {
        repo: &'static str,
        rev: &'static str,
    },
    /// npm-installed at a pinned version into target/bench-tools/node, invoked
    /// via the .bin shim. Pays Node startup but NOT npx resolution overhead —
    /// the fair "as-installed" measurement. Requires a bench-setup install step.
    Npm {
        package: &'static str,
        version: &'static str,
        bin: &'static str,
    },
    /// npx-resolved (no install). Simpler, but each run pays npx resolution on
    /// top of Node. Kept for tools you don't want to pre-install.
    Npx {
        spec: &'static str,
    },
    LocalBuild,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Group {
    Tokenized,
    ByteCount,
}

pub struct Tool {
    pub name: &'static str,
    pub provision: Provision,
    pub group: Group,
    /// Runs under Node → time and peak-RSS include runtime baseline.
    pub node_overhead: bool,
    /// True if this tool's token TOTAL is on the same encoding (o200k) as the
    /// reference set. False = its token column carries a footnote and can't be
    /// ranked against o200k tools (e.g. code2prompt is cl100k-max). Time,
    /// memory, and file count remain comparable regardless.
    pub token_comparable: bool,
    /// True if this tool performs secret scanning (for `bench-secret`).
    pub scans_secrets: bool,
    /// argv for a normalized EXTRACTION run (scanning off where the tool allows).
    pub build_cmd: fn(bin: &str, repo: &Path, sink: &Path) -> Vec<String>,
    /// argv for a SCANNING-ON run, if the tool scans. None otherwise.
    pub build_scan_cmd: Option<fn(bin: &str, repo: &Path, sink: &Path) -> Vec<String>>,
    /// Counts files the tool emitted, by parsing `sink`.
    pub count_files: fn(sink: &Path) -> Option<usize>,
}

pub fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "gnaw",
            provision: Provision::LocalBuild,
            group: Group::Tokenized,
            node_overhead: false,
            token_comparable: true, // o200k
            scans_secrets: true,    // gitleaks
            build_cmd: |bin, repo, sink| {
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--encoding".into(),
                    "o200k".into(),
                    "--secret-scan".into(),
                    "off".into(),
                    "--output-format".into(),
                    "xml".into(),
                    "--quiet".into(),
                    "-O".into(),
                    sink.display().to_string(),
                ]
            },
            build_scan_cmd: Some(|bin, repo, sink| {
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--encoding".into(),
                    "o200k".into(),
                    "--secret-scan".into(),
                    "warn".into(),
                    "--output-format".into(),
                    "xml".into(),
                    "--quiet".into(),
                    "-O".into(),
                    sink.display().to_string(),
                ]
            }),
            count_files: |sink| count_matches(sink, |l| l.trim() == "</file>"),
        },
        Tool {
            name: "code2prompt",
            provision: Provision::Cargo {
                crate_name: "code2prompt",
                version: "4.3.0",
            },
            group: Group::Tokenized,
            node_overhead: false,
            token_comparable: true, // accepts o200k at runtime (help understates it)
            scans_secrets: false,
            build_cmd: |bin, repo, sink| {
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "-O".into(),
                    sink.display().to_string(),
                    "-F".into(),
                    "xml".into(),
                    "--encoding".into(),
                    "o200k".into(), // was cl100k — runtime accepts o200k
                    "--quiet".into(),
                ]
            },
            build_scan_cmd: None,
            count_files: |sink| count_matches(sink, |l| l.trim_start().starts_with("<file")),
        },
        Tool {
            name: "yek",
            provision: Provision::CargoGit {
                repo: "mohsen1/yek",
                rev: "0.25.5",
            },
            group: Group::Tokenized,
            node_overhead: false,
            // yek's --tokens uses its own counter; whether it's o200k is
            // unconfirmed. Assume NOT comparable until verified.
            token_comparable: false,
            scans_secrets: false,
            build_cmd: |bin, repo, sink| {
                let dir = sink.parent().unwrap_or_else(|| Path::new("."));
                let name = sink
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("yek.out");
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--tokens".into(),
                    "16000k".into(),
                    "--output-dir".into(),
                    dir.display().to_string(),
                    "--output-name".into(),
                    name.into(),
                ]
            },
            build_scan_cmd: None,
            count_files: |sink| count_matches(sink, |l| l.starts_with(">>>> ")),
        },
        Tool {
            name: "repomix-rs",
            // Built from source in the builder stage (no arm64 npm prebuilt), copied
            // into the final image as /usr/local/bin/repomix-rs. Native Rust binary now
            // — a fair Rust-vs-Rust row, not an npm/Node-wrapped one. rev MUST match the
            // Dockerfile's `cargo install --git ... --rev`.
            provision: Provision::CargoGit {
                repo: "sopaco/repomix-rs",
                rev: "5798dc0ffb79b3b99b3781040f844d56e9bb36ef",
            },
            group: Group::Tokenized,
            node_overhead: false, // native binary — no Node startup asterisk
            // No `--token-count-encoding` flag exists; it hardcodes its tokenizer.
            // Assumed o200k_base — confirm via the token total before trusting the row.
            token_comparable: true,
            scans_secrets: false,
            build_cmd: |bin, repo, sink| {
                // Positional `root` = dir to pack. --style xml is the default but kept
                // explicit for the record. --compress stays OFF (tree-sitter compression
                // = different work; raw-vs-raw only).
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--output".into(),
                    sink.display().to_string(),
                    "--style".into(),
                    "xml".into(),
                ]
            },
            build_scan_cmd: None,
            count_files: |sink| count_matches(sink, |l| l.trim_start().starts_with("<file path=")),
        },
        Tool {
            name: "repomix",
            provision: Provision::Npm {
                package: "repomix",
                version: "1.16.0",
                bin: "repomix",
            },
            group: Group::Tokenized,
            node_overhead: true,
            token_comparable: true,
            scans_secrets: true,
            build_cmd: |bin, repo, sink| {
                // was |_bin, ...|
                vec![
                    bin.into(), // resolved .bin shim, NOT "npx"
                    repo.display().to_string(),
                    "--output".into(),
                    sink.display().to_string(),
                    "--style".into(),
                    "xml".into(),
                    "--token-count-encoding".into(),
                    "o200k_base".into(),
                    "--no-security-check".into(),
                    "--quiet".into(),
                ]
            },
            build_scan_cmd: Some(|bin, repo, sink| {
                // was |_bin, ...|
                vec![
                    bin.into(),
                    repo.display().to_string(),
                    "--output".into(),
                    sink.display().to_string(),
                    "--style".into(),
                    "xml".into(),
                    "--token-count-encoding".into(),
                    "o200k_base".into(),
                    "--quiet".into(),
                ]
            }),
            count_files: |sink| count_matches(sink, |l| l.trim_start().starts_with("<file path=")),
        },
    ]
}

fn count_matches(sink: &Path, pred: fn(&str) -> bool) -> Option<usize> {
    let text = std::fs::read_to_string(sink).ok()?;
    Some(text.lines().filter(|l| pred(l)).count())
}

// xtask/src/bench/analyze.rs
//! `cargo xtask bench-analyze <report.json>` — re-render a saved benchmark
//! artifact as a markdown table, without re-running the benchmark.
//!
//! This is the reporting half of the measure/report split: a pure function over
//! the JSON that `bench-compare --out <path>` wrote. Re-summarize an old run,
//! regenerate the article's table months later from a committed results.json,
//! all with zero corpus access.

use anyhow::{Context, Result};
use std::path::PathBuf;

use super::report::{BenchReport, render_markdown};

pub fn analyze(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = args.next().map(PathBuf::from).context(
        "bench-analyze needs a path to the report JSON \
         (produced by `cargo xtask bench-compare --out <path>`)",
    )?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading bench report {}", path.display()))?;
    let report: BenchReport = serde_json::from_str(&text)
        .with_context(|| format!("parsing {} as a bench report", path.display()))?;
    print!("{}", render_markdown(&report));
    Ok(())
}

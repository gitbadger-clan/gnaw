// xtask/src/bench/report.rs
//! The shared benchmark artifact + its markdown rendering.
//!
//! The measure step (`bench-compare`) serializes a `BenchReport` to JSON; the
//! report step (`bench-analyze`) reads it back and renders. One schema for both,
//! so a single expensive run can be re-summarized forever without re-running,
//! and the two paths can't disagree about what a "row" is.
//!
//! Rendering enforces the two rules the raw hyperfine JSON can't:
//!   - completeness: a tool that processed >1% fewer files than the most
//!     complete tool isn't doing the same work, so its time ratio is flagged.
//!   - provenance: corpus / image digest / cpu+mem caps travel WITH the numbers,
//!     so the table is citable on its own.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub meta: BenchMeta,
    pub rows: Vec<BenchRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchMeta {
    /// Corpus path or identifier. Pin to a commit SHA for citation.
    pub corpus: String,
    /// Runs used for the resource (peak RSS / cpu×) pass.
    #[serde(default)]
    pub resource_runs: usize,
    /// Provenance — populated when known (e.g. from env in the container run),
    /// omitted from JSON when absent so the artifact stays clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>, // e.g. "gnaw-bench@sha256:…"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>, // ISO-8601; Option avoids a date-crate dep
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRow {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub node_overhead: bool,
    // timing (from hyperfine), all ms; None if the tool was skipped.
    pub mean_ms: Option<f64>,
    pub stddev_ms: Option<f64>,
    pub min_ms: Option<f64>,
    pub max_ms: Option<f64>,
    // resource + completeness.
    pub peak_rss_kb: Option<u64>,
    pub cpu_ratio: Option<f64>,
    pub files: Option<usize>,
}

/// A tool >1% short of the most complete tool isn't doing the same work.
const COMPLETENESS_TOL: f64 = 0.01;

/// Render the report as a sorted markdown table. Fastest first; ratio is
/// mean/mean vs the fastest row, flagged when a row's file count diverges.
pub fn render_markdown(report: &BenchReport) -> String {
    let mut rows: Vec<&BenchRow> = report.rows.iter().collect();
    rows.sort_by(|a, b| match (a.mean_ms, b.mean_ms) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let max_files = report.rows.iter().filter_map(|r| r.files).max();
    let incomplete = |r: &BenchRow| match (r.files, max_files) {
        (Some(f), Some(mx)) if mx > 0 => (f as f64) < (mx as f64) * (1.0 - COMPLETENESS_TOL),
        _ => false,
    };
    // Baseline = fastest mean overall.
    let baseline = rows.iter().find_map(|r| r.mean_ms);
    let baseline_incomplete = rows
        .iter()
        .find(|r| r.mean_ms.is_some())
        .is_some_and(|r| incomplete(r));

    let mut out = String::new();
    out.push_str("| tool | mean ± σ | min … max | vs fastest | files | peak RSS | cpu× | version | notes |\n");
    out.push_str("|---|---|---|---:|---:|---:|---:|---|---|\n");

    let mut any_flag = false;
    for r in &rows {
        let flag = incomplete(r);
        any_flag |= flag;

        let minmax = match (r.min_ms, r.max_ms) {
            (Some(lo), Some(hi)) => format!("{} … {}", fmt_ms(lo), fmt_ms(hi)),
            _ => "—".into(),
        };
        let ratio = match (r.mean_ms, baseline) {
            (Some(m), Some(b)) if b > 0.0 => {
                let s = format!("{:.2}×", m / b);
                if flag { format!("{s} ⚠") } else { s }
            }
            _ => "—".into(),
        };
        let files = match r.files {
            Some(f) if flag => format!("{f} ⚠"),
            Some(f) => f.to_string(),
            None => "?".into(),
        };
        let rss = r
            .peak_rss_kb
            .map(|k| format!("{:.0} MB", k as f64 / 1024.0))
            .unwrap_or_else(|| "—".into());
        let cpu = r
            .cpu_ratio
            .map(|c| format!("{c:.1}"))
            .unwrap_or_else(|| "—".into());
        let notes = if r.node_overhead {
            "incl. Node startup"
        } else {
            ""
        };

        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r.name,
            fmt_pair(r.mean_ms, r.stddev_ms),
            minmax,
            ratio,
            files,
            rss,
            cpu,
            r.version,
            notes
        ));
    }

    out.push('\n');
    if baseline_incomplete {
        out.push_str("**⚠ The fastest row is itself incomplete** — it processed fewer files than the most complete tool, so every `vs fastest` ratio is measured against a tool doing less work. Treat the ranking as invalid until the corpus/config is fixed.\n\n");
    } else if any_flag {
        out.push_str("⚠ Rows marked ⚠ processed >1% fewer files than the most complete tool — their time and `vs fastest` are not valid comparisons (a tool faster on fewer files isn't faster).\n\n");
    }
    out.push_str("`vs fastest` = mean/mean vs the fastest row · `cpu×` = (usr+sys)/wall, >1 means multi-core · `incl. Node startup` rows carry a runtime baseline in both time and peak RSS that native tools don't pay.\n");

    out.push_str(&format!("\nCorpus: `{}`", report.meta.corpus));
    if let Some(v) = &report.meta.image {
        out.push_str(&format!(" · image `{v}`"));
    }
    if let (Some(c), Some(m)) = (&report.meta.cpus, &report.meta.memory) {
        out.push_str(&format!(" · `--cpus {c} --memory {m}`"));
    }
    if report.meta.resource_runs > 0 {
        out.push_str(&format!(" · {} resource runs", report.meta.resource_runs));
    }
    if let Some(d) = &report.meta.created {
        out.push_str(&format!(" · {d}"));
    }
    out.push('\n');
    out
}

fn fmt_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2} s", ms / 1000.0)
    } else {
        format!("{:.0} ms", ms)
    }
}
fn fmt_pair(mean: Option<f64>, sd: Option<f64>) -> String {
    match mean {
        Some(m) => {
            let s = sd.unwrap_or(0.0);
            if m >= 1000.0 {
                format!("{:.2} ± {:.2} s", m / 1000.0, s / 1000.0)
            } else {
                format!("{:.0} ± {:.0} ms", m, s)
            }
        }
        None => "—".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, mean: f64, files: usize) -> BenchRow {
        BenchRow {
            name: name.into(),
            version: "x".into(),
            node_overhead: false,
            mean_ms: Some(mean),
            stddev_ms: Some(mean * 0.05),
            min_ms: Some(mean * 0.9),
            max_ms: Some(mean * 1.1),
            peak_rss_kb: Some(300_000),
            cpu_ratio: Some(4.0),
            files: Some(files),
        }
    }

    #[test]
    fn ratios_and_sort() {
        let rep = BenchReport {
            meta: BenchMeta {
                corpus: "/corpus".into(),
                resource_runs: 5,
                image: None,
                cpus: None,
                memory: None,
                created: None,
            },
            rows: vec![row("slow", 2000.0, 1000), row("fast", 1000.0, 1000)],
        };
        let md = render_markdown(&rep);
        // fast row first, ratio 1.00×; slow 2.00×
        let fast_line = md.lines().find(|l| l.contains("| fast |")).unwrap();
        let slow_line = md.lines().find(|l| l.contains("| slow |")).unwrap();
        assert!(
            md.find("| fast |").unwrap() < md.find("| slow |").unwrap(),
            "fast must sort first"
        );
        assert!(fast_line.contains("1.00×"));
        assert!(slow_line.contains("2.00×"));
        assert!(
            !md.contains('⚠'),
            "equal file counts → no completeness flag"
        );
    }

    #[test]
    fn completeness_flags_short_tool() {
        let rep = BenchReport {
            meta: BenchMeta {
                corpus: "/corpus".into(),
                resource_runs: 5,
                image: None,
                cpus: None,
                memory: None,
                created: None,
            },
            rows: vec![row("full", 2000.0, 1000), row("short", 1000.0, 900)],
        };
        let md = render_markdown(&rep);
        // the fast one is incomplete → strong baseline warning
        assert!(md.contains("fastest row is itself incomplete"));
        assert!(md.contains("900 ⚠"));
    }
}

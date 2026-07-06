//! `cargo xtask bench-regress` — did gnaw get slower than it used to be?
//!
//! The twin of `bench-compare`, with the opposite priorities:
//!   - gnaw ONLY (no competitors) — this is self-vs-self.
//!   - BARE METAL, never Docker — regression detection needs real I/O, real
//!     cores, and the smallest noise floor. A container's VM-I/O and cgroup-CPU
//!     variance can be larger than the regression you're hunting, hiding it.
//!   - A GATE: it exits non-zero past a threshold, mirroring `check-gitleaks`.
//!     So it slots into the same CI pattern as the ruleset staleness check.
//!
//! The threshold is deliberately LOOSE. CI runners are shared, virtualized, and
//! variable; a tight bound produces flaky failures that erode trust until
//! someone disables the check. Catch 2x regressions, not 10% ones. Precise
//! numbers belong on a quiet local machine, which is the other reason this is
//! bare-metal and CI carries only a coarse guard.
//!
//! Two modes:
//!   --against <git-ref>  Build gnaw at <ref> AND at HEAD, race them with
//!                        hyperfine, fail if HEAD is slower by > threshold.
//!                        Use before cutting a release ("did I regress vs the
//!                        last tag?").
//!   --baseline <file>    Compare a fresh HEAD run against a stored mean (ms) in
//!                        <file>, fail if slower by > threshold. The CI-gate
//!                        mode: no second build, just "is HEAD slower than the
//!                        committed floor?". Writes the file if absent (record
//!                        the current number as the new baseline).

use anyhow::{Context, Result, bail, ensure};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default: fail only if HEAD is >25% slower. Loose on purpose (see module doc).
const DEFAULT_THRESHOLD_PCT: f64 = 25.0;

pub fn regress(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut repo: Option<PathBuf> = None;
    let mut against: Option<String> = None;
    let mut baseline: Option<PathBuf> = None;
    let mut threshold_pct = DEFAULT_THRESHOLD_PCT;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--repo" => repo = Some(PathBuf::from(args.next().context("--repo needs a path")?)),
            "--against" => against = Some(args.next().context("--against needs a git ref")?),
            "--baseline" => {
                baseline = Some(PathBuf::from(
                    args.next().context("--baseline needs a file path")?,
                ))
            }
            "--threshold-pct" => {
                threshold_pct = args
                    .next()
                    .context("--threshold-pct needs a number")?
                    .parse()
                    .context("--threshold-pct must be a number")?;
            }
            other => bail!("unknown bench-regress arg {other:?}"),
        }
    }

    let repo = repo
        .context("bench-regress needs --repo <path> (a fixed corpus; pin it for stable numbers)")?;
    ensure!(
        repo.is_dir(),
        "corpus {} is not a directory",
        repo.display()
    );
    ensure!(
        against.is_some() ^ baseline.is_some(),
        "pass exactly one of --against <ref> or --baseline <file>",
    );

    require_tool(
        "hyperfine",
        "brew install hyperfine  # or: cargo install hyperfine",
    )?;

    if let Some(ref_name) = against {
        regress_against_ref(&repo, &ref_name, threshold_pct)
    } else {
        regress_against_baseline(&repo, &baseline.unwrap(), threshold_pct)
    }
}

/// Build HEAD and <ref>, race with hyperfine, gate on the ratio.
fn regress_against_ref(repo: &Path, ref_name: &str, threshold_pct: f64) -> Result<()> {
    let root = super::workspace_root();

    // Current tree → release binary, copied aside so building <ref> can't clobber it.
    build_release()?;
    let head_bin = stash_binary(&root, "gnaw-head")?;

    // Build <ref> in a throwaway worktree so we don't disturb the working tree.
    // A worktree (not a checkout) keeps HEAD and the index untouched — safer in
    // CI and locally than `git checkout <ref>` which mutates the working copy.
    let worktree = root.join("target/bench-regress-worktree");
    git(&[
        "worktree",
        "add",
        "--force",
        "--detach",
        worktree.to_str().unwrap(),
        ref_name,
    ])
    .with_context(|| format!("adding worktree at {ref_name}"))?;
    let ref_bin = {
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "gnaw-ctx"])
            .current_dir(&worktree)
            .status()
            .context("building gnaw at ref")?;
        ensure!(status.success(), "building gnaw at {ref_name} failed");
        stash_binary_from(&worktree.join("target/release/gnaw"), &root, "gnaw-ref")?
    };
    // Clean up the worktree regardless of what happens next.
    let _ = git(&["worktree", "remove", "--force", worktree.to_str().unwrap()]);

    let json = std::env::temp_dir().join("gnaw-regress.json");
    race(&ref_bin, &head_bin, repo, &json)?;

    let means = parse_two(&json)?; // (ref_ms, head_ms) keyed by command name
    let (ref_ms, head_ms) = means;
    report_and_gate(ref_name, ref_ms, head_ms, threshold_pct)
}

/// Compare a fresh HEAD run against a stored baseline mean (ms).
fn regress_against_baseline(repo: &Path, baseline_file: &Path, threshold_pct: f64) -> Result<()> {
    let root = super::workspace_root();
    build_release()?;
    let head_bin = root.join("target/release/gnaw");
    ensure!(head_bin.exists(), "gnaw release binary missing");

    let json = std::env::temp_dir().join("gnaw-regress-baseline.json");
    let head_ms = single(&head_bin, repo, &json)?;

    if !baseline_file.exists() {
        std::fs::write(baseline_file, format!("{head_ms:.3}\n"))
            .with_context(|| format!("writing baseline {}", baseline_file.display()))?;
        println!("no baseline found; recorded current mean {head_ms:.1}ms as new baseline");
        println!("  {}", baseline_file.display());
        return Ok(());
    }

    let base_ms: f64 = std::fs::read_to_string(baseline_file)
        .context("reading baseline")?
        .trim()
        .parse()
        .context("baseline file must contain a single number (ms)")?;
    report_and_gate("baseline", base_ms, head_ms, threshold_pct)
}

/// The gate: print the verdict, exit(1) if HEAD regressed past the threshold.
/// Mirrors check-gitleaks' shape exactly.
fn report_and_gate(base_label: &str, base_ms: f64, head_ms: f64, threshold_pct: f64) -> Result<()> {
    let delta_pct = (head_ms - base_ms) / base_ms * 100.0;
    println!("bench-regress:");
    println!("  {base_label:<10} {base_ms:>9.1}ms");
    println!("  HEAD       {head_ms:>9.1}ms   ({delta_pct:+.1}%)");

    if delta_pct > threshold_pct {
        println!(
            "REGRESSION: HEAD is {delta_pct:.1}% slower than {base_label} \
             (threshold {threshold_pct:.0}%)"
        );
        std::process::exit(1);
    }
    println!("ok: within {threshold_pct:.0}% threshold");
    Ok(())
}

// ---- hyperfine helpers ----

/// Race two binaries; JSON keyed "ref" and "head".
fn race(ref_bin: &Path, head_bin: &Path, repo: &Path, out: &Path) -> Result<()> {
    let status = Command::new("hyperfine")
        .arg("--warmup")
        .arg("3")
        .arg("--export-json")
        .arg(out)
        .arg("--command-name")
        .arg("ref")
        .arg(bench_cmd(ref_bin, repo))
        .arg("--command-name")
        .arg("head")
        .arg(bench_cmd(head_bin, repo))
        .status()
        .context("spawning hyperfine")?;
    ensure!(status.success(), "hyperfine failed");
    Ok(())
}

/// Single HEAD run; return its mean in ms.
fn single(bin: &Path, repo: &Path, out: &Path) -> Result<f64> {
    let status = Command::new("hyperfine")
        .arg("--warmup")
        .arg("3")
        .arg("--export-json")
        .arg(out)
        .arg("--command-name")
        .arg("head")
        .arg(bench_cmd(bin, repo))
        .status()
        .context("spawning hyperfine")?;
    ensure!(status.success(), "hyperfine failed");
    parse_one(out, "head")
}

/// The canonical regression command: extraction only, sink to /dev/null, o200k,
/// scanner off — isolates gnaw's own extraction speed, the thing we're tracking.
fn bench_cmd(bin: &Path, repo: &Path) -> String {
    format!(
        "{} {} --encoding o200k --secret-scan off --quiet -O /dev/null",
        bin.display(),
        repo.display(),
    )
}

fn parse_one(path: &Path, name: &str) -> Result<f64> {
    let v = read_json(path)?;
    for r in v
        .get("results")
        .and_then(|r| r.as_array())
        .context("no results[]")?
    {
        if r.get("command").and_then(|c| c.as_str()) == Some(name) {
            return Ok(r.get("mean").and_then(|m| m.as_f64()).context("no mean")? * 1000.0);
        }
    }
    bail!("command {name:?} not in hyperfine output");
}

fn parse_two(path: &Path) -> Result<(f64, f64)> {
    Ok((parse_one(path, "ref")?, parse_one(path, "head")?))
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path).context("reading hyperfine json")?;
    serde_json::from_str(&text).context("parsing hyperfine json")
}

// ---- build / binary stashing ----

fn build_release() -> Result<()> {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "gnaw-ctx"])
        .status()
        .context("cargo build")?;
    ensure!(status.success(), "release build failed");
    Ok(())
}

/// Copy target/release/gnaw aside under a distinct name so a later build for a
/// different ref doesn't overwrite the one we still need to benchmark.
fn stash_binary(root: &Path, as_name: &str) -> Result<PathBuf> {
    stash_binary_from(&root.join("target/release/gnaw"), root, as_name)
}
fn stash_binary_from(src: &Path, root: &Path, as_name: &str) -> Result<PathBuf> {
    let dir = root.join("target/bench-bins");
    std::fs::create_dir_all(&dir).ok();
    let dst = dir.join(as_name);
    std::fs::copy(src, &dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(dst)
}

fn git(args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .status()
        .context("spawning git")?;
    ensure!(status.success(), "git {:?} failed", args);
    Ok(())
}

fn require_tool(name: &str, hint: &str) -> Result<()> {
    if which::which(name).is_err() {
        bail!("{name} not found. Install:\n  {hint}");
    }
    Ok(())
}

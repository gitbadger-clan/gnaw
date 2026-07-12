//! `cargo xtask bench-compare` — gnaw vs the field, on one repo, honestly.
//!
//! Two passes, deliberately separate (learned the hard way):
//!   1. TIMING   — hyperfine `--warmup 3 --export-json`. Statistical wall-clock.
//!      Never wrap the command in `/usr/bin/time` here; that contaminates it.
//!   2. RESOURCE — a `/usr/bin/time` loop, few runs, take max RSS + the
//!      CPU-to-wall ratio. Peak RSS is kernel-tracked (exact), far more stable
//!      run-to-run than wall time, so it doesn't need hyperfine's machinery.
//!
//! Then MERGE both, plus completeness (files processed), into one table:
//! tool · mean time · peak RSS · CPU ratio · files · version · asterisks.
//! The completeness column is not optional — a tool faster on fewer files isn't
//! faster, and that's where it shows.
//!
//! Three entry points share ONE measurement core (`measure_and_report`):
//! - `compare`       : host path. Parses args, builds gnaw, may hand off to
//!   Docker, else measures locally.
//! - `compare_inner` : runs INSIDE the pinned image. gnaw + competitors are on
//!   PATH; corpus is baked at --repo. No build, no resolve.
//!   Same core, both environments — so the fairness rules in `tools.rs` are the
//!   single source of truth and can't drift.

use anyhow::{Context, Result, bail, ensure};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::report::{BenchMeta, BenchReport, BenchRow};
use super::tools::{self, Group, Provision, Tool};

/// One tool's merged row, ready to print.
struct Row {
    name: String,
    version: String,
    group: Group,
    node_overhead: bool,
    mean_ms: Option<f64>,     // from hyperfine
    stddev_ms: Option<f64>,   // from hyperfine
    min_ms: Option<f64>,      // from hyperfine
    max_ms: Option<f64>,      // from hyperfine
    peak_rss_kb: Option<u64>, // from /usr/bin/time max over runs
    cpu_ratio: Option<f64>,   // (usr+sys)/wall; >1 ⇒ multi-core
    files: Option<usize>,     // completeness: what it actually emitted
}

/// Which argv a tool runs for a measurement pass. Extraction = the normalized
/// "scanning off where allowed" run; Scanning = "scanning on", and only tools
/// that scan (build_scan_cmd = Some) participate.
#[derive(Clone, Copy, PartialEq)]
pub enum Pass {
    Extraction,
    Scanning,
}

/// argv for `t` in `pass`. None ⇒ the tool doesn't do this pass (a non-scanning
/// tool under Scanning) and is filtered out before we get here.
fn pass_argv(t: &Tool, pass: Pass, bin: &str, repo: &Path, sink: &Path) -> Option<Vec<String>> {
    match pass {
        Pass::Extraction => Some((t.build_cmd)(bin, repo, sink)),
        Pass::Scanning => t.build_scan_cmd.map(|f| f(bin, repo, sink)),
    }
}

/// Host entry point: `cargo xtask bench-compare [--repo <p> | --docker ...]`.
pub fn compare(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut repo: Option<PathBuf> = None;
    let mut resource_runs = 5usize;
    // Docker opts, collected in the same loop (parsing stays in the frontend).
    let mut docker = false;
    let mut image = "gnaw-bench:latest".to_string();
    let mut cpus = "8".to_string();
    let mut memory = "8g".to_string();
    let mut build_image = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--repo" => repo = Some(PathBuf::from(args.next().context("--repo needs a path")?)),
            "--resource-runs" => {
                resource_runs = args
                    .next()
                    .context("--resource-runs needs a number")?
                    .parse()
                    .context("--resource-runs must be an integer")?;
            }
            "--docker" => docker = true,
            "--image" => image = args.next().context("--image needs a tag/digest")?,
            "--cpus" => cpus = args.next().context("--cpus needs a value")?,
            "--memory" => memory = args.next().context("--memory needs a value")?,
            "--build-image" => build_image = true,
            other => bail!("unknown bench-compare arg {other:?}"),
        }
    }

    // Docker path: hand off to the container, which runs `bench-compare-inner`
    // (the SAME measurement core). --repo is ignored; the corpus is baked into
    // the image at a pinned SHA.
    if docker {
        return super::docker::run(&super::docker::DockerOpts {
            image,
            cpus,
            memory,
            build: build_image,
        });
    }

    // Host path: measure locally against --repo with a freshly built gnaw.
    let repo = repo.context(
        "bench-compare needs --repo <path> (a checkout at a pinned commit), \
         or --docker to use the pinned image",
    )?;
    ensure!(
        repo.is_dir(),
        "corpus path {} is not a directory",
        repo.display()
    );

    build_gnaw_release()?;
    let root = super::workspace_root();
    let gnaw_bin = root.join("target/release/gnaw");
    ensure!(
        gnaw_bin.exists(),
        "gnaw release binary missing at {}",
        gnaw_bin.display()
    );

    measure_and_report(
        &repo,
        resource_runs,
        Some(&gnaw_bin),
        &root,
        None,
        Pass::Extraction,
    )
}

/// Container entry point: `xtask bench-compare-inner --repo /corpus --out /out`.
/// gnaw + competitors are on PATH; corpus is baked. No build, no bench-tools
/// resolution — the Dockerfile already installed everything.
pub fn compare_inner(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut repo: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut resource_runs = 5usize;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--repo" => repo = Some(PathBuf::from(args.next().context("--repo needs a path")?)),
            "--out" => out = Some(PathBuf::from(args.next().context("--out needs a path")?)),
            "--resource-runs" => {
                resource_runs = args
                    .next()
                    .context("--resource-runs needs a number")?
                    .parse()
                    .context("--resource-runs must be an integer")?;
            }
            other => bail!("unknown bench-compare-inner arg {other:?}"),
        }
    }
    let repo = repo.context("bench-compare-inner needs --repo (the baked corpus, e.g. /corpus)")?;

    // gnaw_bin: None → resolve gnaw from PATH. root is unused for PATH tools but
    // required by the signature; workspace_root() is harmless in-container.
    let root = super::workspace_root();
    measure_and_report(
        &repo,
        resource_runs,
        None,
        &root,
        out.as_deref(),
        Pass::Extraction,
    )
}

/// `cargo xtask bench-secret --repo <p> [--out <p>]` — scanning-ON speed + memory
/// for the tools that scan (gnaw, repomix, repomix-rs). Same core as bench-compare.
pub fn secret(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut repo: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut resource_runs = 5usize;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--repo" => repo = Some(PathBuf::from(args.next().context("--repo needs a path")?)),
            "--out" => out = Some(PathBuf::from(args.next().context("--out needs a path")?)),
            "--resource-runs" => {
                resource_runs = args
                    .next()
                    .context("--resource-runs needs a number")?
                    .parse()
                    .context("--resource-runs must be an integer")?;
            }
            other => bail!("unknown bench-secret arg {other:?}"),
        }
    }
    let repo = repo.context("bench-secret needs --repo <path> (a checkout at a pinned commit)")?;
    ensure!(
        repo.is_dir(),
        "corpus path {} is not a directory",
        repo.display()
    );

    build_gnaw_release()?;
    let root = super::workspace_root();
    let gnaw_bin = root.join("target/release/gnaw");
    ensure!(
        gnaw_bin.exists(),
        "gnaw release binary missing at {}",
        gnaw_bin.display()
    );

    measure_and_report(
        &repo,
        resource_runs,
        Some(&gnaw_bin),
        &root,
        out.as_deref(),
        Pass::Scanning,
    )
}

/// Container entry: `xtask bench-secret-inner --repo /corpus [--out /out]`.
pub fn secret_inner(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut repo: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut resource_runs = 5usize;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--repo" => repo = Some(PathBuf::from(args.next().context("--repo needs a path")?)),
            "--out" => out = Some(PathBuf::from(args.next().context("--out needs a path")?)),
            "--resource-runs" => {
                resource_runs = args
                    .next()
                    .context("--resource-runs needs a number")?
                    .parse()
                    .context("--resource-runs must be an integer")?;
            }
            other => bail!("unknown bench-secret-inner arg {other:?}"),
        }
    }
    let repo = repo.context("bench-secret-inner needs --repo (the baked corpus, e.g. /corpus)")?;
    let root = super::workspace_root();
    measure_and_report(
        &repo,
        resource_runs,
        None,
        &root,
        out.as_deref(),
        Pass::Scanning,
    )
}

/// The shared measurement core: two passes + merge + report. Called by both the
/// host path (with a locally built gnaw) and the container path (gnaw on PATH).
/// This is the single source of truth for how tools are measured.
fn measure_and_report(
    repo: &Path,
    resource_runs: usize,
    gnaw_bin: Option<&Path>,
    root: &Path,
    out: Option<&Path>,
    pass: Pass,
) -> Result<()> {
    // The measurement tools must exist. GNU time is Linux (/usr/bin/time);
    // macOS ships BSD time with different flags — run the comparison in the
    // Linux bench image.
    require_tool(
        "hyperfine",
        "brew install hyperfine  # or: cargo install hyperfine",
    )?;
    require_path(
        "/usr/bin/time",
        "apt-get install time  (GNU time; run in the Linux bench image)",
    )?;

    let all = tools::tools();
    let sink_dir = std::env::temp_dir().join("gnaw-bench");
    std::fs::create_dir_all(&sink_dir).ok();

    // Resolve each tool to (exec, sink). Skip-with-warning if not provisioned —
    // a contributor won't have all of them, and that must degrade gracefully.
    let mut resolved: Vec<(Tool, String, PathBuf)> = Vec::new();
    for t in all {
        if pass == Pass::Scanning && !t.scans_secrets {
            continue; // doesn't scan → not part of the secret pass
        }
        let sink = sink_dir.join(format!("{}.out", t.name));
        let exec = match resolve_exec(&t, gnaw_bin, root) {
            Some(e) => e,
            None => {
                eprintln!(
                    "skip {}: not provisioned (run `cargo xtask bench-setup`)",
                    t.name
                );
                continue;
            }
        };
        resolved.push((t, exec, sink));
    }
    ensure!(
        !resolved.is_empty(),
        "no tools resolved; nothing to benchmark"
    );

    // ---- PASS 1: TIMING via hyperfine (all tools, one invocation) ----
    let hf_json = sink_dir.join("timing.json");
    run_hyperfine(&resolved, repo, &hf_json, pass)?;
    let timing = parse_hyperfine(&hf_json)?; // name → (mean_ms, stddev_ms)

    // ---- PASS 2: RESOURCE via /usr/bin/time (separate, per tool) ----
    let mut resource: std::collections::HashMap<String, (u64, f64)> = Default::default();
    for (t, exec, sink) in &resolved {
        let argv =
            pass_argv(t, pass, exec, repo, sink).expect("resolved tool has an argv for this pass");
        let (peak_kb, ratio) = measure_resource(&argv, resource_runs)
            .with_context(|| format!("resource pass for {}", t.name))?;
        resource.insert(t.name.to_string(), (peak_kb, ratio));
    }

    // ---- MERGE + completeness ----
    let mut rows: Vec<Row> = Vec::new();
    for (t, _exec, sink) in &resolved {
        let (mean_ms, stddev_ms, min_ms, max_ms) = timing
            .get(t.name)
            .map(|&(m, s, lo, hi)| (Some(m), Some(s), Some(lo), Some(hi)))
            .unwrap_or((None, None, None, None));
        let (peak, ratio) = resource
            .get(t.name)
            .map(|&(p, r)| (Some(p), Some(r)))
            .unwrap_or((None, None));
        rows.push(Row {
            name: t.name.to_string(),
            version: resolve_version(&t.provision),
            group: t.group,
            node_overhead: t.node_overhead,
            mean_ms,
            stddev_ms,
            min_ms,
            max_ms,
            peak_rss_kb: peak,
            cpu_ratio: ratio,
            files: (t.count_files)(sink),
        });
    }

    print_report(&rows, repo, pass);
    if let Some(out) = out {
        let report = BenchReport {
            meta: BenchMeta {
                corpus: repo.display().to_string(),
                resource_runs,
                image: std::env::var("GNAW_BENCH_IMAGE").ok(),
                cpus: std::env::var("GNAW_BENCH_CPUS").ok(),
                memory: std::env::var("GNAW_BENCH_MEMORY").ok(),
                created: None,
            },
            rows: rows
                .iter()
                .map(|r| BenchRow {
                    name: r.name.clone(),
                    version: r.version.clone(),
                    node_overhead: r.node_overhead,
                    mean_ms: r.mean_ms,
                    stddev_ms: r.stddev_ms,
                    min_ms: r.min_ms,
                    max_ms: r.max_ms,
                    peak_rss_kb: r.peak_rss_kb,
                    cpu_ratio: r.cpu_ratio,
                    files: r.files,
                })
                .collect(),
        };
        std::fs::write(out, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("writing bench report {}", out.display()))?;
    }
    Ok(())
}

/// hyperfine drives all tools at once so warmup/cache state is shared.
fn run_hyperfine(
    resolved: &[(Tool, String, PathBuf)],
    repo: &Path,
    out_json: &Path,
    pass: Pass,
) -> Result<()> {
    let mut cmd = Command::new("hyperfine");
    cmd.arg("--warmup")
        .arg("3")
        .arg("--export-json")
        .arg(out_json);
    // Prime any npx download once so the fetch never lands in a timed run.
    for (t, exec, sink) in resolved {
        if let Provision::Npx { .. } = t.provision
            && let Some(argv) = pass_argv(t, pass, exec, repo, sink)
        {
            cmd.arg("--setup").arg(argv.join(" "));
        }
    }
    for (t, exec, sink) in resolved {
        let argv =
            pass_argv(t, pass, exec, repo, sink).expect("resolved tool has an argv for this pass");
        cmd.arg("--command-name").arg(t.name);
        cmd.arg(argv.join(" "));
    }
    let status = cmd.status().context("spawning hyperfine")?;
    ensure!(status.success(), "hyperfine exited non-zero");
    Ok(())
}

/// Parse hyperfine's JSON → name → (mean_ms, stddev_ms).
fn parse_hyperfine(path: &Path) -> Result<std::collections::HashMap<String, (f64, f64, f64, f64)>> {
    let text = std::fs::read_to_string(path).context("reading hyperfine json")?;
    let v: serde_json::Value = serde_json::from_str(&text).context("parsing hyperfine json")?;
    let mut out = std::collections::HashMap::new();
    for r in v
        .get("results")
        .and_then(|r| r.as_array())
        .context("no results[]")?
    {
        let name = r
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or("?")
            .to_string();
        // hyperfine reports seconds; convert to ms.
        let mean = r.get("mean").and_then(|x| x.as_f64()).unwrap_or(f64::NAN) * 1000.0;
        let stddev = r.get("stddev").and_then(|x| x.as_f64()).unwrap_or(f64::NAN) * 1000.0;
        let min = r.get("min").and_then(|x| x.as_f64()).unwrap_or(f64::NAN) * 1000.0;
        let max = r.get("max").and_then(|x| x.as_f64()).unwrap_or(f64::NAN) * 1000.0;
        out.insert(name, (mean, stddev, min, max));
    }
    Ok(out)
}

/// One resource run: `/usr/bin/time -f '%e %U %S %M' argv...`, parse the last
/// stderr line. Repeat `runs` times; return (max_peak_kb, cpu_ratio_at_max).
fn measure_resource(argv: &[String], runs: usize) -> Result<(u64, f64)> {
    let mut best_peak = 0u64;
    let mut ratio_at_best = 0.0;
    for _ in 0..runs {
        let out = Command::new("/usr/bin/time")
            .arg("-f")
            .arg("%e %U %S %M")
            .args(argv)
            .output()
            .context("spawning /usr/bin/time")?;
        // /usr/bin/time writes its line to stderr, last line.
        let stderr = String::from_utf8_lossy(&out.stderr);
        let line = stderr.lines().last().unwrap_or_default();
        let f: Vec<f64> = line
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        if f.len() == 4 {
            let (wall, usr, sys, peak) = (f[0], f[1], f[2], f[3] as u64);
            if peak > best_peak {
                best_peak = peak;
                ratio_at_best = if wall > 0.0 { (usr + sys) / wall } else { 0.0 };
            }
        }
    }
    ensure!(best_peak > 0, "no valid /usr/bin/time output parsed");
    Ok((best_peak, ratio_at_best))
}

fn build_gnaw_release() -> Result<()> {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "gnaw-ctx"])
        .status()
        .context("spawning cargo build")?;
    ensure!(status.success(), "gnaw release build failed");
    Ok(())
}

/// Resolve a tool's executable. gnaw → local release bin (host) or PATH
/// (container). Cargo/CargoGit → target/bench-tools/bin/<name> then PATH.
/// Npx → "npx" (spec is in the argv).
fn resolve_exec(t: &Tool, gnaw_bin: Option<&Path>, root: &Path) -> Option<String> {
    match &t.provision {
        Provision::LocalBuild => match gnaw_bin {
            Some(b) => Some(b.display().to_string()), // host: local build
            None => which::which("gnaw").ok().map(|p| p.display().to_string()), // container: PATH
        },
        Provision::Npm { package, bin, .. } => {
            let base = std::env::var("BENCH_TOOLS_DIR")
                .unwrap_or_else(|_| root.join("target/bench-tools").display().to_string());
            let shim = Path::new(&base)
                .join("node")
                .join(package)
                .join("node_modules/.bin")
                .join(bin);
            shim.exists().then(|| shim.display().to_string())
        }
        Provision::Npx { .. } => which::which("npx").ok().map(|p| p.display().to_string()),
        Provision::Cargo { crate_name, .. } => {
            let local = root.join("target/bench-tools/bin").join(crate_name);
            if local.exists() {
                Some(local.display().to_string())
            } else {
                which::which(crate_name)
                    .ok()
                    .map(|p| p.display().to_string())
            }
        }
        Provision::CargoGit { .. } => {
            let local = root.join("target/bench-tools/bin").join(t.name);
            if local.exists() {
                Some(local.display().to_string())
            } else {
                which::which(t.name).ok().map(|p| p.display().to_string())
            }
        }
    }
}

fn resolve_version(p: &Provision) -> String {
    match p {
        Provision::Cargo { version, .. } => (*version).into(),
        Provision::CargoGit { rev, .. } => format!("git:{rev}"),
        Provision::Npm {
            package, version, ..
        } => format!("{package}@{version}"),
        Provision::Npx { spec } => (*spec).into(),
        Provision::LocalBuild => "local".into(),
    }
}

fn require_tool(name: &str, hint: &str) -> Result<()> {
    if which::which(name).is_err() {
        bail!("{name} not found. Install:\n  {hint}");
    }
    Ok(())
}
fn require_path(path: &str, hint: &str) -> Result<()> {
    if !Path::new(path).exists() {
        bail!("{path} not found. Install:\n  {hint}");
    }
    Ok(())
}

/// The report: timing table + completeness/version companion + the disclosures
/// that make it citable. Facts a reader needs to reproduce and trust the numbers.
fn print_report(rows: &[Row], repo: &Path, pass: Pass) {
    let title = match pass {
        Pass::Extraction => "bench-compare (extraction)",
        Pass::Scanning => "bench-secret (scanning on)",
    };
    println!("\n=== {title} ===");
    println!("\n=== bench-compare ===");
    println!("corpus: {}", repo.display());
    println!(
        "(pin this to a commit SHA in the methodology; run on a Linux host \
         for representative I/O)\n"
    );

    println!(
        "{:<14} {:>12} {:>10} {:>7} {:>9}  {:<16} notes",
        "tool", "mean", "peak RSS", "cpu×", "files", "version"
    );
    for r in rows {
        let mean = r
            .mean_ms
            .map(|m| {
                let s = r.stddev_ms.unwrap_or(0.0);
                if m >= 1000.0 {
                    format!("{:.2}±{:.2}s", m / 1000.0, s / 1000.0)
                } else {
                    format!("{:.0}±{:.0}ms", m, s)
                }
            })
            .unwrap_or_else(|| "—".into());
        let rss = r
            .peak_rss_kb
            .map(|k| format!("{:.0}MB", k as f64 / 1024.0))
            .unwrap_or_else(|| "—".into());
        let cpu = r
            .cpu_ratio
            .map(|c| format!("{:.1}", c))
            .unwrap_or_else(|| "—".into());
        let files = r.files.map(|f| f.to_string()).unwrap_or_else(|| "?".into());
        let mut notes = Vec::new();
        if r.node_overhead {
            notes.push("incl. Node startup");
        }
        if r.group == Group::ByteCount {
            notes.push("byte-count group");
        }
        println!(
            "{:<14} {:>12} {:>10} {:>7} {:>9}  {:<16} {}",
            r.name,
            mean,
            rss,
            cpu,
            files,
            r.version,
            notes.join("; ")
        );
    }

    println!("\ndisclosures:");
    println!(
        "  · files column = what each tool emitted. Counts must match (~within \
         1%) for the time comparison to be valid — a tool faster on fewer files \
         isn't faster."
    );
    println!(
        "  · cpu× = (usr+sys)/wall. >1 means multi-core; gnaw's parallelism \
         shows here and explains why it wins at scale but ties on tiny inputs."
    );
    println!(
        "  · 'incl. Node startup' rows carry runtime baseline in BOTH time and \
         peak RSS that native tools don't pay."
    );
    match pass {
        Pass::Extraction => println!(
            "  · gnaw ran --secret-scan off (extraction-speed number). Scanning \
             cost is the separate `bench-secret` pass."
        ),
        Pass::Scanning => println!(
            "  · scanning ON. gnaw=gitleaks ruleset, repomix=Secretlint, \
             repomix-rs=custom regex set (scans by default; its extraction row \
             already included this — subtract to see others' scan tax)."
        ),
    }
}

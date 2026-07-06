//! Docker orchestration for `bench-compare --docker`.
//!
//! The host does NOT measure here. It builds/pulls the pinned image (gnaw +
//! competitors + corpus + the xtask binary, all baked in) and runs the SAME
//! measurement code INSIDE the container via `bench-compare-inner`. Only an
//! output dir is mounted; the corpus lives in the image at a pinned SHA, so
//! reads are native-Linux, not host-VM — the reason Docker is right for the
//! *comparison* benchmark (reproducible ranking) and wrong for regression
//! tracking (which wants bare-metal noise floor).
//!
//! One source of truth: the fairness rules live in `tools.rs`. Baking the xtask
//! binary into the image and running that exact code in-container means the
//! normalization (yek `--tokens`, o200k, node-overhead) can't drift from a
//! second host-side copy. That's why we run `xtask bench-compare-inner` rather
//! than generating hyperfine shell strings on the host.
//!
//! hyperfine runs INSIDE the container (not `docker run` per tool from the
//! host), so timing happens in the measured environment and we never time
//! container startup on each invocation.

use anyhow::{Context, Result, bail, ensure};
use std::process::Command;

/// Pinned run parameters. Every field is DISCLOSED in the methodology — the
/// pins are what make the number citable, and `--cpus` in particular is an
/// editorial choice (it can tilt tools that parallelize differently), so it is
/// reported, never silent.
pub struct DockerOpts {
    /// Image tag or digest. A digest (`sha256:...`) is the most reproducible.
    pub image: String,
    /// Pinned CPU allocation, e.g. "8".
    pub cpus: String,
    /// Pinned memory ceiling, e.g. "8g".
    pub memory: String,
    /// If true, `docker build` from benchmarks/ before running; else assume the
    /// tag/digest already exists (pulled or previously built).
    pub build: bool,
}

pub fn run(opts: &DockerOpts) -> Result<()> {
    require_docker()?;

    if opts.build {
        build_image(&opts.image)?;
    }

    // Host dir to receive whatever the container writes to /out.
    let out_host = std::env::temp_dir().join("gnaw-bench-docker");
    std::fs::create_dir_all(&out_host)
        .with_context(|| format!("creating {}", out_host.display()))?;

    // Run the inner benchmark in the container. Corpus is /corpus (baked in);
    // results land in /out (mounted). --cpus/--memory pin resources so the
    // ranking is reproducible and the allocation is a disclosed constant.
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--cpus",
            &opts.cpus,
            "--memory",
            &opts.memory,
            "-v",
            &format!("{}:/out", out_host.display()),
            &opts.image,
            // The image bakes the xtask binary on PATH (see benchmarks/Dockerfile).
            // Same code as the host path, minus build/resolve: it measures
            // /corpus and writes /out.
            "xtask",
            "bench-compare-inner",
            "--repo",
            "/corpus",
            "--out",
            "/out",
        ])
        .status()
        .context("spawning docker run")?;
    ensure!(status.success(), "containerized benchmark failed");

    // The inner run streamed its table to stdout via docker. Point at any
    // machine-readable artifact and print the methodology line that makes the
    // result reproducible.
    println!(
        "\nmethodology: image {}, --cpus {}, --memory {}, corpus baked at pinned SHA",
        opts.image, opts.cpus, opts.memory
    );
    println!(
        "record the image digest as the citable artifact:\n  \
         docker inspect --format '{{{{.Id}}}}' {}",
        opts.image
    );
    if out_host.join("report.txt").exists() {
        println!("extracted results: {}", out_host.display());
    }
    Ok(())
}

/// Build the image from benchmarks/Dockerfile with the workspace root as the
/// build context (the Dockerfile `COPY . /build`s to compile gnaw + xtask).
fn build_image(tag: &str) -> Result<()> {
    let root = super::workspace_root();
    let dockerfile = root.join("benchmarks/Dockerfile");
    ensure!(
        dockerfile.exists(),
        "no Dockerfile at {}",
        dockerfile.display()
    );
    let status = Command::new("docker")
        .args([
            "build",
            "-f",
            dockerfile.to_str().context("dockerfile path not utf-8")?,
            "-t",
            tag,
            root.to_str().context("root path not utf-8")?,
        ])
        .status()
        .context("spawning docker build")?;
    ensure!(status.success(), "docker build failed");
    Ok(())
}

fn require_docker() -> Result<()> {
    if which::which("docker").is_err() {
        bail!("docker not found. Install Docker to run the reproducible comparison.");
    }
    Ok(())
}

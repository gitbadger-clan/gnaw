//! Workspace dev tasks, run via `cargo xtask <task>`.
//!
//! - `update-gitleaks [version]` vendors a gitleaks release's ruleset at
//!   crates/gnaw-core/assets/gitleaks.toml. With no version it resolves the
//!   latest release. This is a MAINTAINER task, not a build step — the file is
//!   committed and the build reads it via `include_str!` (no network at build).
//! - `check-gitleaks` reports whether the vendored ruleset is behind the latest
//!   release; exits non-zero if it is (handy locally and as a CI gate).

mod bench;
use std::path::Path;

use anyhow::{Context, Result, bail};

const DEST: &str = "crates/gnaw-core/assets/gitleaks.toml";
const RELEASES_LATEST: &str = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("update-gitleaks") => update_gitleaks(args.next()),
        Some("check-gitleaks") => check_gitleaks(),
        Some("bench-compare") => bench::compare(args),
        Some("bench-compare-inner") => bench::compare_inner(args),
        Some("bench-regress") => bench::regress(args),
        other => bail!(
            "unknown task {other:?}\n  usage:\n    \
             cargo xtask update-gitleaks [version]\n    \
             cargo xtask check-gitleaks\n    \
             cargo xtask bench-compare [--docker] [--cpus N]\n    \
             cargo xtask bench-regress [--against <ref>]"
        ),
    }
}

/// Latest non-prerelease gitleaks tag, e.g. "v8.28.0".
fn latest_release_tag() -> Result<String> {
    let tag = ureq::get(RELEASES_LATEST)
        .header("User-Agent", "gnaw-xtask") // GitHub rejects requests without a UA
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("querying gitleaks releases")?
        .body_mut()
        .read_json::<serde_json::Value>()
        .context("parsing release JSON")?
        .get("tag_name")
        .and_then(|v| v.as_str())
        .context("no tag_name in release response")?
        .to_string();
    Ok(tag)
}

/// Tag recorded in the vendored file's provenance stamp, if present.
fn vendored_version() -> Option<String> {
    let text = std::fs::read_to_string(DEST).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("# Vendored from gitleaks "))
        .map(|v| v.trim().to_string())
}

fn check_gitleaks() -> Result<()> {
    let latest = latest_release_tag()?;
    match vendored_version() {
        Some(v) if v == latest => {
            println!("up to date: gitleaks {v}");
            Ok(())
        }
        Some(v) => {
            println!("update available: vendored {v}, latest {latest}");
            println!("  run: cargo xtask update-gitleaks");
            std::process::exit(1);
        }
        None => {
            println!("no vendored ruleset found; latest is {latest}");
            println!("  run: cargo xtask update-gitleaks");
            std::process::exit(1);
        }
    }
}

fn update_gitleaks(version: Option<String>) -> Result<()> {
    let version = match version {
        Some(v) => v,
        None => latest_release_tag()?,
    };
    let url = format!(
        "https://raw.githubusercontent.com/gitleaks/gitleaks/{version}/config/gitleaks.toml"
    );
    println!("Fetching gitleaks ruleset {version}\n  from {url}");

    let body = ureq::get(&url)
        .header("User-Agent", "gnaw-xtask")
        .call()
        .with_context(|| format!("fetching {url} (is {version} a real release tag?)"))?
        .body_mut()
        .read_to_string()
        .context("reading response body")?;

    // Provenance + license stamp at the top (TOML comments) so the version is
    // visible in diffs. `vendored_version()` reads the first line back.
    let stamped = format!(
        "# Vendored from gitleaks {version}\n\
         # Source: {url}\n\
         # Refresh: cargo xtask update-gitleaks [version]\n\
         # gitleaks is MIT licensed (https://github.com/gitleaks/gitleaks).\n\n\
         {body}"
    );

    let dest = Path::new(DEST);
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(dest, stamped).with_context(|| format!("writing {DEST}"))?;

    println!("Wrote {DEST}");
    println!("Next: cargo test -p gnaw-core gitleaks   # confirms the compile rate");
    Ok(())
}

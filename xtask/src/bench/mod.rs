//! Benchmark orchestration. Like the gitleaks tasks, these are MAINTAINER
//! tasks, not build steps. They don't measure anything themselves — they set up
//! fair, reproducible conditions and shell out to `hyperfine` (timing) and
//! `/usr/bin/time` (peak RSS + CPU), then merge the artifacts into one table.
//!
//! Two distinct benchmarks, deliberately separate:
//! - `bench-compare`: gnaw vs other context builders. Periodic, human-read,
//!   published. Runs in a pinned Docker image for reproducibility (`--docker`),
//!   or locally against `--repo`. The in-container half is `bench-compare-inner`.
//! - `bench-regress`: gnaw vs a past release. Bare-metal, CI-gated; exits
//!   non-zero past a threshold, mirroring `check-gitleaks`'s gate semantics.
//!
//! Shared: `tools.rs` (the pinned provisioning + invocation table) and
//! `compare::measure_and_report` (the single measurement core both the host and
//! container paths call, so the fairness rules can't drift).

mod compare;
mod docker;
mod regress;
mod tools;

use std::path::Path;

pub use compare::{compare, compare_inner};
pub use regress::regress;

/// Locate the workspace root from xtask's manifest dir (xtask is one level down).
/// Both benchmarks need this to find the release binary and the corpus.
pub(crate) fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is a workspace member; parent is the root")
        .to_path_buf()
}

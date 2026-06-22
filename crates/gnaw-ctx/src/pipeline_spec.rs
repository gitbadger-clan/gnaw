//! Re-export shim. The pipeline composition root moved to the `gnaw-pipeline`
//! crate so the CLI, MCP server, Python bindings, and the planned REST surface
//! share one `build_spec`/`run_extraction` instead of each keeping a copy.
//!
//! This module exists only so the existing `crate::pipeline_spec::…` call sites
//! in `main.rs` keep resolving unchanged. New code can call `gnaw_pipeline::…`
//! directly; once the call sites are migrated, delete this file and the
//! `mod pipeline_spec;` line.
pub use gnaw_pipeline::{build_renderer_for, build_spec, run_extraction};

//! Composition root for gnaw's extraction pipeline.
//!
//! ONE `build_spec(config)` chooses the source, chunker, tree builder, and
//! renderer template from a `GnawConfig`; `run_extraction(config)` builds that
//! spec and runs it end to end. Every frontend — the CLI, the MCP server, the
//! Python bindings, and the planned REST surface — calls these instead of
//! hand-wiring adapters, so the "which adapter for which config" policy lives
//! in exactly one place and can't drift between frontends.
//!
//! This crate sits above `gnaw-adapters` (which stays a pure adapter library,
//! unaware of how configs map onto adapters) and below the frontends.

use anyhow::Result;
use gnaw_adapters::git::{get_git_diff, get_git_diff_between_branches, get_git_log};
use gnaw_adapters::{
    ChangedChunker, ChangedPathsSource, ChangedScope, CommitRangeSource, FullWalkTree,
    HandlebarsRenderer, IdentityChunker, ItemsTree, PassThrough, PatternSelector, RendererConfig,
    SecretScrubber, StdinContentSource, StdinPathsSource, TakeUntilBudget, TiktokenCounter,
    Uniform, WorkingTreeSource,
};
use gnaw_core::builtin_templates::BuiltinTemplates;
use gnaw_core::configuration::GnawConfig;
use gnaw_core::path::display_name;
use gnaw_core::pipeline::ports::{Chunker, ContextSource, Selector, TreeBuilder};
use gnaw_core::pipeline::{PipelineSpec, Rendered, SourceOpts, run};

/// Build the extraction spec for `config`. The run kind is chosen here from
/// config alone — frontends never pick adapters directly.
///
/// `stdin_paths == Some` → piped-paths view: `StdinPathsSource` sources exactly
/// the files named on stdin (no walk), paired with a `PassThrough` selector
/// since the piped list is itself the selection. Takes precedence over the git
/// axes — if you piped a path list, that's what you meant to extract.
///
/// `diff_shas == Some` → changed-files view: `CommitRangeSource` (no working-tree
/// walk — the whole reason the token bug dies), `ChangedChunker` (per-file
/// blocks, keeps binaries), the git-diff-shas-pipeline template, and an
/// items-derived tree listing only touched files.
///
/// `diff_shas == None` → working-tree view: `WorkingTreeSource`, `IdentityChunker`,
/// the configured/default template, and an items-derived tree — or a full
/// filesystem walk under `--full-directory-tree`, which must show filter-dropped
/// paths and so cannot derive from items.
pub fn build_spec(config: &GnawConfig) -> Result<PipelineSpec> {
    // The piped path list is authoritative — it bypasses include/exclude
    // filtering (the user named exactly these files). `extract_raw_file` still
    // drops binaries/empties and the Scrubber stage still guards secrets, so
    // PassThrough here is no leakier than the pattern path.
    let selector: Box<dyn Selector> = if config.stdin_paths.is_some() {
        Box::new(PassThrough)
    } else {
        Box::new(PatternSelector::new(
            &config.include_patterns,
            &config.exclude_patterns,
        ))
    };
    let scrubber = Box::new(SecretScrubber::new(config));
    let ranker = Box::new(Uniform);
    let budgeter = Box::new(TakeUntilBudget::new(Box::new(TiktokenCounter::new(
        config.encoding,
    ))));
    // Renderer template comes from the same diff_shas axis, but through the
    // shared helper that build_renderer_for also uses — so a split part can't
    // drift from a whole run.
    let renderer = Box::new(HandlebarsRenderer::new(renderer_config_for(config)?));
    let root_label = display_name(&config.path);

    // Source, chunker, and tree builder vary by run kind.
    let (source, chunker, tree_builder): (
        Box<dyn ContextSource>,
        Box<dyn Chunker>,
        Box<dyn TreeBuilder>,
    ) = if let Some(text) = config.stdin_content.clone() {
        // Piped CONTENT: one synthetic item named `stdin`. Highest precedence —
        // mutually exclusive with stdin_paths by construction (classify_stdin
        // sets exactly one), but ordered first so a bug there fails visibly.
        (
            Box::new(StdinContentSource::new(text)),
            Box::new(IdentityChunker),
            Box::new(ItemsTree),
        )
    } else if let Some(paths) = config.stdin_paths.clone() {
        // stdin paths: source exactly the piped files; items-derived tree of
        // just those files. No working-tree walk.
        (
            Box::new(StdinPathsSource::new(config.clone(), paths)),
            Box::new(IdentityChunker),
            Box::new(ItemsTree),
        )
    } else if let Some((ref1, ref2)) = config.diff_shas.clone() {
        // --git-diff-shas: per-file patch content, rendered inline.
        (
            Box::new(CommitRangeSource::new(config.clone(), ref1, ref2)),
            Box::new(ChangedChunker),
            Box::new(ItemsTree),
        )
    } else if let Some(scope) = git_narrative_scope(config) {
        // commit / changeset / PR: changed-files tree, diff+log rendered as
        // chrome. Source yields paths only (Omitted) → IdentityChunker drops
        // them → no content chunks; the template renders {{git_diff}} etc.
        (
            Box::new(ChangedPathsSource::new(config.clone(), scope)),
            Box::new(IdentityChunker),
            Box::new(ItemsTree),
        )
    } else {
        // whole repo
        let tree: Box<dyn TreeBuilder> = if config.full_directory_tree {
            Box::new(FullWalkTree::new(config.clone()))
        } else {
            Box::new(ItemsTree)
        };
        (
            Box::new(WorkingTreeSource::new(config.clone())),
            Box::new(IdentityChunker),
            tree,
        )
    };

    Ok(PipelineSpec {
        source,
        selector,
        chunker,
        scrubber,
        ranker,
        budgeter,
        renderer,
        tree_builder,
        budget: 0,
        root_label,
        sort_method: config.sort_method,
        progress: None,
    })
}

/// Build and run the extraction spec end to end. The one-call entry every
/// frontend uses for a non-split run.
pub fn run_extraction(config: &GnawConfig) -> Result<Rendered> {
    let spec = build_spec(config)?;
    let rendered = run(&spec, &SourceOpts)?;
    Ok(rendered)
}

fn default_renderer_config(config: &GnawConfig) -> Result<RendererConfig> {
    // The pipeline has no git stage, so the frontend loads git context and
    // hands it to the renderer as top-level chrome — exactly what the legacy
    // load_git_diff / _between_branches / _log methods did.
    //
    // Errors propagate here; legacy only warned and continued. That divergence
    // is deliberate: a requested --diff that can't be produced should fail, not
    // silently render a diff-less prompt (the regression we're fixing). If you
    // want legacy's behavior back, swap `?` for `.ok()` on each call.
    let git_diff = if config.diff_enabled {
        Some(get_git_diff(&config.path, config.diff_mode)?)
    } else {
        None
    };
    let git_diff_branch = match &config.diff_branches {
        Some((a, b)) => Some(get_git_diff_between_branches(&config.path, a, b)?),
        None => None,
    };
    let git_log_branch = match &config.log_branches {
        Some((a, b)) => Some(get_git_log(&config.path, a, b)?),
        None => None,
    };
    Ok(RendererConfig {
        no_codeblock: config.no_codeblock,
        line_numbers: config.line_numbers,
        git_diff,
        git_diff_branch,
        git_log_branch,
        template_str: config.template_str.clone(),
        template_name: config.template_name.clone(),
        output_format: config.output_format,
        user_variables: config.user_variables.clone(),
    })
}

/// Renderer config for the changed-files view: resolves the built-in
/// git-diff-shas-pipeline template unless the user set an explicit one.
fn changed_renderer_config(config: &GnawConfig) -> Result<RendererConfig> {
    let (template_str, template_name) = if config.template_str.is_empty() {
        let t = BuiltinTemplates::get_template("git-diff-shas-pipeline")
            .ok_or_else(|| anyhow::anyhow!("builtin git-diff-shas-pipeline template missing"))?;
        (t.content.to_string(), "git-diff-shas-pipeline".to_string())
    } else {
        (config.template_str.clone(), config.template_name.clone())
    };
    Ok(RendererConfig {
        no_codeblock: config.no_codeblock,
        line_numbers: config.line_numbers,
        git_diff: None,
        git_diff_branch: None,
        git_log_branch: None,
        template_str,
        template_name,
        output_format: config.output_format,
        user_variables: config.user_variables.clone(),
    })
}

/// The single place the "which template" decision lives. Both `build_spec` and
/// `build_renderer_for` route through it, so a changed-files split part renders
/// with the same template as a changed-files whole run — guaranteed by
/// construction, not by remembering to keep two branches in sync.
fn renderer_config_for(config: &GnawConfig) -> Result<RendererConfig> {
    if config.diff_shas.is_some() {
        changed_renderer_config(config)
    } else {
        default_renderer_config(config)
    }
}

/// Build the renderer matching whichever extraction `config` selects, so a split
/// part renders byte-identically to a whole run. Used by the CLI split path,
/// which renders each part via `render_subset`.
pub fn build_renderer_for(config: &GnawConfig) -> Result<HandlebarsRenderer> {
    Ok(HandlebarsRenderer::new(renderer_config_for(config)?))
}

/// For a git-narrative run, where the changed-file list comes from: a branch
/// pair (PR) or the working tree (commit/changeset). `None` → not a changed-
/// files run, use the whole-repo source. Reads `config.git_narrative`, set at
/// config-build time from the resolved template — this no longer sniffs a
/// template name. A git-narrative template with no git context (e.g. bare
/// `--template write-git-commit`) yields `None` and renders the whole tree.
fn git_narrative_scope(config: &GnawConfig) -> Option<ChangedScope> {
    if !config.git_narrative {
        return None;
    }
    if let Some((b1, b2)) = config
        .diff_branches
        .clone()
        .or_else(|| config.log_branches.clone())
    {
        Some(ChangedScope::Refs(b1, b2)) // PR
    } else if config.diff_enabled {
        Some(ChangedScope::WorkingTree(config.diff_mode)) // commit / changeset
    } else {
        None
    }
}

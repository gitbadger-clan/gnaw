//! The runner: the ONE place the stage sequence lives. A frontend builds a
//! `PipelineSpec` naming which adapter fills each slot; the runner threads
//! data stage-to-stage and returns the rendered result. No business logic
//! here — just the wiring order.
//!
//! Source → Filter → Chunk → (Rank) → Budget(+Count) → Render.
//! Counting is internal to the budget stage (the budgeter holds the counter),
//! so the tally is computed once from exactly what's kept.
//!
//! Per-stage timing is emitted at `debug` on the `gnaw::timing` target. It's
//! off unless you ask for it — e.g. `RUST_LOG=gnaw::timing=debug gnaw .` —
//! and the `Instant` reads are negligible next to the stage work, so they run
//! unconditionally and only the logging is gated.

use super::*;
use crate::pipeline::dto::{Selection, TokenTally};
use std::time::Instant;

/// Declares which adapter fills each pipeline slot. Trait objects so a
/// frontend composes a spec at runtime (CLI picks a source from flags; a REST
/// handler picks one from a request body). Boxed because sizes differ and the
/// spec outlives any single stack frame in the server case.
pub struct PipelineSpec {
    pub source: Box<dyn ContextSource>,
    pub selector: Box<dyn Selector>,
    pub chunker: Box<dyn Chunker>,
    pub ranker: Box<dyn Ranker>,
    pub budgeter: Box<dyn Budgeter>,
    pub renderer: Box<dyn Renderer>,
    /// 0 = unbudgeted (keep everything), matching the budgeter's convention.
    pub budget: usize,
    /// Root node label for the source tree (use `display_name(&config.path)`).
    pub root_label: String,
    /// Sort order for the items-derived tree; must match the config used to
    /// capture the golden or the default tree ordering drifts.
    pub sort_method: Option<crate::sort::FileSortMethod>,
    pub tree_builder: Box<dyn TreeBuilder>,
    pub scrubber: Box<dyn Scrubber>,
}

/// Run the pipeline end to end.
pub fn run(spec: &PipelineSpec, opts: &SourceOpts) -> Result<Rendered, PipelineError> {
    let overall = Instant::now();
    let mut t = Instant::now();

    // Source: yield raw items.
    let items = spec.source.items(opts)?;
    log::debug!(target: "gnaw::timing", "source:       {:>9.2?}  ({} items)", t.elapsed(), items.len());
    t = Instant::now();

    // Filter: drop out-of-scope items. Order preserved (determinism).
    let items: Vec<RawItem> = items
        .into_iter()
        .filter(|it| spec.selector.keep(it))
        .collect();
    log::debug!(target: "gnaw::timing", "filter:       {:>9.2?}  ({} kept)", t.elapsed(), items.len());
    t = Instant::now();

    // Scrub: scan for secrets BEFORE chunking (whole-file scan, matching
    // legacy). Findings ride to the end independent of budgeting.
    let (items, findings) = spec.scrubber.scrub(items);
    log::debug!(target: "gnaw::timing", "scrub:        {:>9.2?}  ({} findings)", t.elapsed(), findings.len());
    t = Instant::now();

    // ── NEW ── Render context derived from the surviving items. Built HERE,
    // after filtering, so the tree is exactly the set that reaches the output —
    // no separate walk, no binary/empty over-inclusion. This is the double-walk
    // and tree-over-inclusion fix in one place.
    let render_ctx = RenderContext {
        source_tree: spec
            .tree_builder
            .build(&items, &spec.root_label, spec.sort_method),
        absolute_code_path: spec.root_label.clone(),
    };
    log::debug!(target: "gnaw::timing", "tree:         {:>9.2?}", t.elapsed());
    t = Instant::now();

    // Chunk: each item → 0..n chunks.
    let chunks: Vec<Chunk> = items.iter().flat_map(|it| spec.chunker.chunk(it)).collect();
    log::debug!(target: "gnaw::timing", "chunk:        {:>9.2?}  ({} chunks)", t.elapsed(), chunks.len());
    t = Instant::now();

    // Rank: score each chunk.
    let rank_ctx = RankCtx; // ← was `ctx`, renamed for clarity
    let mut ranked: Vec<ScoredChunk> = chunks
        .into_iter()
        .map(|chunk| {
            let score = spec.ranker.score(&chunk, &rank_ctx);
            ScoredChunk { chunk, score }
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    log::debug!(target: "gnaw::timing", "rank:         {:>9.2?}", t.elapsed());
    t = Instant::now();

    // Budget (+count). The budgeter holds the token counter, so this stage
    // includes tokenization — usually the dominant cost on a large repo.
    let selection = spec.budgeter.fit(ranked, spec.budget);
    log::debug!(
        target: "gnaw::timing",
        "budget+count: {:>9.2?}  ({} chunks kept, {} tokens)",
        t.elapsed(),
        selection.chunks.len(),
        selection.tally.total,
    );
    t = Instant::now();

    // Render — now takes the items-derived context as a second argument.
    let rendered = spec.renderer.render(&selection, &render_ctx)?;
    log::debug!(target: "gnaw::timing", "render:       {:>9.2?}", t.elapsed());

    log::debug!(target: "gnaw::timing", "TOTAL:        {:>9.2?}", overall.elapsed());

    Ok(Rendered {
        findings,
        chunks: selection.chunks,
        // Moved, not cloned — `render_ctx` is dead after `render` borrowed it,
        // and this string is codebase-tree-sized. Completes hotspot #2.
        source_tree: render_ctx.source_tree,
        ..rendered
    })
}

/// Render a SUBSET of already-extracted chunks into a standalone document,
/// reusing a precomputed source tree. This is the split primitive: extraction
/// ran once (producing `Rendered.chunks` + `Rendered.source_tree`); each part
/// is one cheap renderer pass over a slice of those chunks against the SAME
/// tree. No source walk, no re-tokenize — chunks already carry `tokens`.
///
/// Lives in core (not gnaw-ctx) so a REST/MCP frontend can split too: a
/// browser extension requesting a budget-fit gets the same per-part assembly.
/// Takes the renderer as a trait object so each frontend supplies its own.
pub fn render_subset(
    renderer: &dyn Renderer,
    source_tree: &str,
    root_label: &str,
    chunks: Vec<Chunk>,
    encoding: &str,
) -> Result<Rendered, PipelineError> {
    // Rebuild the tally for just this subset — sum the per-chunk counts the
    // budgeter already stamped, and the per-path breakdown from the same.
    let mut total = 0usize;
    let mut by_path = std::collections::BTreeMap::new();
    for c in &chunks {
        total += c.tokens;
        *by_path.entry(c.source_path.clone()).or_insert(0) += c.tokens;
    }

    let tally = TokenTally {
        total,
        by_path,
        // ← if TokenTally carries `encoding` (or other fields), set them here.
        encoding: encoding.to_string(),
    };

    let selection = Selection {
        chunks,
        tally,
        // ← if Selection carries `omitted` (or other fields), set them here.
        omitted: Vec::new(),
    };

    let ctx = RenderContext {
        source_tree: source_tree.to_string(),
        absolute_code_path: root_label.to_string(),
    };

    // run() normally overwrites chunks/source_tree/findings on the renderer's
    // output; for a subset render the body is all we want, so the renderer's
    // empty placeholders are fine — we don't re-surface chunks here.
    renderer.render(&selection, &ctx)
}

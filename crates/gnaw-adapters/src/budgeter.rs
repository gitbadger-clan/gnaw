//! "Take until budget" budgeter. Walks scored chunks in order, keeping each
//! until the running token total would exceed the budget, then drops the
//! rest. Owns the invariant `Selection.tally.total <= budget`.
//!
//! Owns its `TokenCounter` (option 1 from the step-3 lifetime fork), so the
//! spec is fully owned with no lifetimes, and the tally is computed HERE,
//! once, from exactly what's kept — no parallel sum to drift from.

use gnaw_core::pipeline::{Budgeter, Chunk, ScoredChunk, Selection, TokenCounter, TokenTally};
use rayon::prelude::*;
use std::collections::BTreeMap;

pub struct TakeUntilBudget {
    counter: Box<dyn TokenCounter>,
}

impl TakeUntilBudget {
    pub fn new(counter: Box<dyn TokenCounter>) -> Self {
        Self { counter }
    }
}

impl Budgeter for TakeUntilBudget {
    fn fit(&self, ranked: Vec<ScoredChunk>, budget: usize) -> Selection {
        // Counting is the dominant cost (tiktoken BPE is CPU/hash-bound) and each
        // count is an independent pure function of the chunk text, so tokenize the
        // whole set up front in parallel. `par_iter().map().collect()` preserves
        // input order, so counts[i] pairs with ranked[i].
        //
        // The budget DECISION below stays sequential and in ranked order, so the
        // kept/omitted sets and the tally are byte-identical to the serial version
        // — only the counting moved off the critical path. (TokenCounter is
        // Send + Sync, so sharing &self.counter across rayon threads is sound.)
        let counts: Vec<usize> = ranked
            .par_iter()
            .map(|sc| self.counter.count(&sc.chunk.text))
            .collect();

        let mut chunks: Vec<Chunk> = Vec::new();
        let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
        let mut total = 0usize;
        let mut omitted: Vec<String> = Vec::new();

        for (sc, tokens) in ranked.into_iter().zip(counts) {
            // budget == 0 means "no budget" — keep everything.
            if budget != 0 && total + tokens > budget {
                omitted.push(sc.chunk.source_path);
                continue;
            }
            total += tokens;
            *by_path.entry(sc.chunk.source_path.clone()).or_insert(0) += tokens;
            let chunk = Chunk { tokens, ..sc.chunk };
            chunks.push(chunk);
        }

        Selection {
            chunks,
            tally: TokenTally {
                total,
                by_path,
                encoding: self.counter.encoding().to_string(),
            },
            omitted,
        }
    }
}

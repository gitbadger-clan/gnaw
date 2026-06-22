//! Concrete pipeline adapters for gnaw: filesystem traversal, git, tokenizing,
//! rendering, and the staged pipeline impls. `gnaw-core` defines the ports
//! (traits) and DTOs; this crate provides the I/O-bound implementations,
//! keeping core free of git2/ignore/content_inspector/rayon.

pub mod git;
pub mod path;

mod budgeter;
mod changed_chunker;
mod chunker;
mod counter;
mod ranker;
mod renderer;
mod scrubber;
mod selector;
mod source;
mod tree;

pub use budgeter::TakeUntilBudget;
pub use changed_chunker::ChangedChunker;
pub use chunker::IdentityChunker;
pub use counter::TiktokenCounter;
pub use ranker::Uniform;
pub use renderer::{HandlebarsRenderer, RendererConfig};
pub use scrubber::SecretScrubber;
pub use selector::{ExplicitSelector, PassThrough, PatternSelector};
pub use source::{
    ChangedPathsSource, ChangedScope, CommitRangeSource, StdinPathsSource, WorkingTreeSource,
};
pub use tree::{FullWalkTree, ItemsTree};

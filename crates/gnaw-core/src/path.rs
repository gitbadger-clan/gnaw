//! Pure path types and helpers shared across the workspace. Filesystem
//! traversal and per-file extraction moved to `gnaw-adapters` so core carries
//! no I/O crates; what remains here is data + pure string/tree shaping.

use crate::sort::{FileSortMethod, sort_tree};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::path::Path;
use termtree::Tree;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub is_dir: bool,
    pub is_symlink: bool,
}

impl From<&std::fs::Metadata> for EntryMetadata {
    fn from(meta: &std::fs::Metadata) -> Self {
        Self {
            is_dir: meta.is_dir(),
            is_symlink: meta.is_symlink(),
        }
    }
}

/// A processed file entry: content plus token count and metadata. Built by the
/// adapter traversal; sorted by `sort::sort_files`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub extension: String,
    pub code: String,
    pub token_count: usize,
    pub metadata: EntryMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mod_time: Option<u64>,
}

/// File name, or the current directory's name, or ".". Pure.
pub fn display_name<P: AsRef<Path>>(p: P) -> String {
    let path = p.as_ref();
    if let Some(name) = path.file_name() {
        return name.to_string_lossy().into_owned();
    }
    if let Ok(cwd) = std::env::current_dir()
        && let Some(name) = cwd.file_name()
    {
        return name.to_string_lossy().into_owned();
    }
    ".".to_string()
}

/// Optionally prefix each line with a line number. Pure; the renderer owns
/// this presentation step now that the source no longer wraps.
pub fn wrap_code_block(code: &str, line_numbers: bool) -> std::borrow::Cow<'_, str> {
    if line_numbers {
        Cow::Owned(
            code.lines()
                .enumerate()
                .map(|(i, l)| format!("{:4} | {}\n", i + 1, l))
                .collect(),
        )
    } else {
        Cow::Borrowed(code)
    }
}

/// Build the source-tree string from already-yielded pipeline items, with no
/// filesystem walk. Pure: it only reshapes `RawItem` paths into a sorted tree,
/// so it stays in core even though the walking sources live in adapters.
pub fn tree_from_items(
    items: &[crate::pipeline::RawItem],
    root_label: &str,
    sort_method: Option<FileSortMethod>,
) -> String {
    let mut tree = Tree::new(root_label.to_owned());
    for item in items {
        let mut current = &mut tree;
        for component in item.path.split('/').filter(|c| !c.is_empty()) {
            let pos = current
                .leaves
                .iter()
                .position(|child| child.root == component);
            current = match pos {
                Some(i) => &mut current.leaves[i],
                None => {
                    current.leaves.push(Tree::new(component.to_owned()));
                    current.leaves.last_mut().unwrap()
                }
            };
        }
    }
    sort_tree(&mut tree, sort_method);
    tree.to_string()
}

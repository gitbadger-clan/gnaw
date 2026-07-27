//! Utility functions for the TUI application.
//!
//! This module contains helper functions for building file trees,
//! managing file operations, and other utility functions used throughout the TUI.

use crate::model::{DisplayFileNode, Message, VisibleRow};
use crate::model::{SizeFilter, TokenState};
use anyhow::Result;
use globset::GlobSet;
use gnaw_core::session::SelectionState;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Collect every leaf file under `node_path`, regardless of selection state,
/// honoring the same ignore/hidden rules as the rest of the walk. Used by the
/// directory Space-toggle to drive a bulk select/deselect over the subtree.
///
/// We walk the filesystem rather than the display tree because a collapsed
/// subtree may not have its children loaded yet.
pub fn collect_files_under(node_path: &Path, session: &SelectionState) -> Vec<PathBuf> {
    let mut out = Vec::new();

    if node_path.is_file() {
        out.push(node_path.to_path_buf());
        return out;
    }

    use ignore::WalkBuilder;
    let walker = WalkBuilder::new(node_path)
        .git_ignore(!session.config.no_ignore)
        .hidden(!session.config.hidden)
        .build();

    for entry in walker.flatten() {
        let p = entry.path();
        if p.is_file() {
            out.push(p.to_path_buf());
        }
    }
    out
}

/// Collect every selected leaf in the already-loaded display tree.
/// Selected files are auto-expanded at build time, so their nodes are loaded.
pub fn collect_selected_files_in_tree(
    nodes: &[DisplayFileNode],
    session: &mut SelectionState,
) -> Vec<PathBuf> {
    fn rec(n: &DisplayFileNode, session: &mut SelectionState, out: &mut Vec<PathBuf>) {
        if n.is_directory {
            for c in &n.children {
                rec(c, session, out);
            }
        } else if session.is_file_selected(&n.path) {
            out.push(n.path.clone());
        }
    }
    let mut out = Vec::new();
    for n in nodes {
        rec(n, session, &mut out);
    }
    out
}

pub fn stream_file_tree(
    session: &mut SelectionState,
    tx: &tokio::sync::mpsc::UnboundedSender<Message>, // match your actual sender type
) -> Result<()> {
    use ignore::WalkBuilder;
    let walker = WalkBuilder::new(&session.config.path)
        .max_depth(Some(1))
        .git_ignore(!session.config.no_ignore)
        .hidden(!session.config.hidden)
        .build();

    for entry in walker {
        let entry = entry?;
        let path = entry.path();
        if path == session.config.path {
            continue;
        }
        let mut node = DisplayFileNode::new(path.to_path_buf(), 0);
        if node.is_directory {
            auto_expand_recursively(&mut node, session);
        }
        // Ship it the moment it's ready. UI merges + re-sorts on arrival.
        if tx.send(Message::FileNodeDiscovered(node)).is_err() {
            break; // receiver gone (app quit) — stop walking
        }
    }
    Ok(())
}

/// Recursively auto-expand directories that contain selected files
fn auto_expand_recursively(node: &mut DisplayFileNode, session: &mut SelectionState) {
    if !node.is_directory {
        return;
    }

    if directory_contains_selected_files(&node.path, session) {
        node.is_expanded = true;
        // Load children
        if let Err(e) = node.load_children(session) {
            eprintln!("Warning: Failed to load children for {}: {}", node.name, e);
            return;
        }

        // Recursively auto-expand children
        for child in &mut node.children {
            if child.is_directory {
                auto_expand_recursively(child, session);
            }
        }
    }
}

/// Check if a directory contains any selected files (helper function)
pub(crate) fn directory_contains_selected_files(
    dir_path: &Path,
    session: &mut SelectionState,
) -> bool {
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let relative_path = if let Ok(rel) = path.strip_prefix(&session.config.path) {
                rel
            } else {
                continue;
            };

            if session.is_file_selected(relative_path) {
                return true;
            }

            // Recursively check subdirectories
            if path.is_dir() && directory_contains_selected_files(&path, session) {
                return true;
            }
        }
    }
    false
}

fn passes_filters(
    node: &DisplayFileNode,
    matcher: &QueryMatcher,
    size_filter: Option<SizeFilter>,
    token_states: &HashMap<PathBuf, TokenState>,
) -> bool {
    let passes_name = matches!(matcher, QueryMatcher::MatchAll)
        || matches(matcher, &node.name)
        || matches(matcher, &node.path.to_string_lossy());
    let passes_size = match (size_filter, node.is_directory) {
        (None, _) | (Some(_), true) => true,
        (Some(filter), false) => match token_states.get(&node.path) {
            Some(TokenState::Done(n)) => match filter {
                SizeFilter::GreaterThan(t) => *n > t,
                SizeFilter::LessThan(t) => *n < t,
            },
            _ => false,
        },
    };
    passes_name && passes_size
}

fn node_is_selected(node: &DisplayFileNode, session: &mut SelectionState) -> bool {
    if node.is_directory {
        dir_is_selected(node, session)
    } else {
        let relative = node
            .path
            .strip_prefix(&session.config.path)
            .unwrap_or(&node.path);
        session.is_file_selected(relative)
    }
}

/// Build one row from a node. `is_expanded` is passed in because the search
/// path displays every directory as open for context without touching the
/// real tree's expansion state.
fn row_for(node: &DisplayFileNode, is_selected: bool, is_expanded: bool) -> VisibleRow {
    VisibleRow {
        path: node.path.clone(),
        name: node.name.clone(),
        level: node.level,
        is_directory: node.is_directory,
        is_expanded,
        is_selected,
        agg_tokens: node.agg_tokens,
    }
}

/// Search mode. A directory is included if it matches *or* anything beneath it
/// does, so children must be resolved before the parent is emitted — hence the
/// per-directory scratch Vec. Rows are flat (no subtree), so that scratch is a
/// handful of small clones, not a deep copy.
///
/// Takes `&mut` because children are loaded into the persistent tree:
/// `children_loaded` makes every subsequent keystroke's rebuild pure in-memory
/// instead of a disk walk.
fn collect_visible_search(
    nodes: &mut [DisplayFileNode],
    matcher: &QueryMatcher,
    size_filter: Option<SizeFilter>,
    token_states: &HashMap<PathBuf, TokenState>,
    session: &mut SelectionState,
    out: &mut Vec<VisibleRow>,
) {
    for node in nodes.iter_mut() {
        let mut child_rows = Vec::new();
        if node.is_directory {
            if !node.children_loaded {
                let _ = node.load_children(session);
            }
            collect_visible_search(
                &mut node.children,
                matcher,
                size_filter,
                token_states,
                session,
                &mut child_rows,
            );
        }

        let matches_current = passes_filters(node, matcher, size_filter, token_states);
        let include_self = matches_current || !child_rows.is_empty();
        if include_self {
            let is_selected = node_is_selected(node, session);
            // Directories render as expanded in search results; files are never
            // expanded, and `node.is_directory` is false for them.
            out.push(row_for(node, is_selected, node.is_directory));
            out.append(&mut child_rows);
        }
    }
}

/// Normal mode: flatten the tree honoring real expansion state. No filesystem
/// access, no tree mutation — everything visible is already loaded.
fn collect_visible_normal(
    nodes: &[DisplayFileNode],
    matcher: &QueryMatcher,
    size_filter: Option<SizeFilter>,
    token_states: &HashMap<PathBuf, TokenState>,
    session: &mut SelectionState,
    out: &mut Vec<VisibleRow>,
) {
    for node in nodes {
        if !passes_filters(node, matcher, size_filter, token_states) {
            continue;
        }
        let is_selected = node_is_selected(node, session);
        out.push(row_for(node, is_selected, node.is_expanded));
        // Only descend if the directory is expanded.
        if node.is_directory && node.is_expanded {
            collect_visible_normal(
                &node.children,
                matcher,
                size_filter,
                token_states,
                session,
                out,
            );
        }
    }
}

/// Get visible rows for display (flattened tree with search filtering).
///
/// `nodes` is `&mut` because the search path memoizes loaded children into the
/// tree. The return value is fully owned, so no borrow of `nodes` outlives the
/// call — callers are free to mutate the tree immediately afterwards.
pub fn get_visible_nodes(
    nodes: &mut [DisplayFileNode],
    search_query: &str,
    size_filter: Option<SizeFilter>,
    token_states: &HashMap<PathBuf, TokenState>,
    session: &mut SelectionState,
) -> Vec<VisibleRow> {
    let matcher = build_query_matcher(search_query);
    let mut visible = Vec::new();
    if search_query.is_empty() {
        collect_visible_normal(
            nodes,
            &matcher,
            size_filter,
            token_states,
            session,
            &mut visible,
        );
    } else {
        collect_visible_search(
            nodes,
            &matcher,
            size_filter,
            token_states,
            session,
            &mut visible,
        );
    }
    visible
}

/// A directory's *display* selection is derived from its contents: it shows as
/// selected when at least one leaf beneath it (over the already-loaded children)
/// is selected. Folders carry no selection action of their own under per-file
/// selection, so querying the engine for the directory path would always return
/// the default — this keeps the checkbox honest after bulk/partial (de)selection.
fn dir_is_selected(node: &DisplayFileNode, session: &mut SelectionState) -> bool {
    for child in &node.children {
        if child.is_directory {
            if dir_is_selected(child, session) {
                return true;
            }
        } else if session.is_file_selected(&child.path) {
            return true;
        }
    }
    false
}

/// Matcher for the file-tree search box.
/// - No glob metacharacters (`* ? {`) → case-insensitive substring (interactive default).
/// - Any metacharacter → full glob dialect via the shared build_globset (braces, **, etc.),
///   matched against name and path, same engine as --include/--exclude.
enum QueryMatcher {
    Substr(String),
    Glob(GlobSet),
    MatchAll,
}

fn build_query_matcher(raw: &str) -> QueryMatcher {
    let raw = raw.trim();
    if raw.is_empty() {
        return QueryMatcher::MatchAll;
    }

    let has_glob = raw.contains('*') || raw.contains('?') || raw.contains('{');
    if !has_glob {
        return QueryMatcher::Substr(raw.to_lowercase());
    }

    // Reuse the filter's globset (brace expansion + **/ prefixing + case fold).
    // Lowercase the pattern and match against lowercased text below for case-insensitivity,
    // since globset itself is case-sensitive.
    QueryMatcher::Glob(gnaw_core::filter::build_globset(&[raw.to_lowercase()]))
}

fn matches(m: &QueryMatcher, text: &str) -> bool {
    match m {
        QueryMatcher::MatchAll => true,
        QueryMatcher::Substr(needle) => text.to_lowercase().contains(needle),
        QueryMatcher::Glob(set) => set.is_match(text.to_lowercase()),
    }
}

/// Save content to a file
pub fn save_to_file(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    Ok(())
}

/// Format a number with thousand separators according to TokenFormat
///
/// - TokenFormat::Raw: returns the number as-is (e.g., "1234567")
/// - TokenFormat::Format: adds separators every 3 digits (e.g., "1,234,567")
///
/// # Arguments
/// * `num` - The number to format
/// * `format` - The token format setting
///
/// # Returns
/// Formatted string representation of the number
pub fn format_number(num: usize, format: &gnaw_core::tokenizer::TokenFormat) -> String {
    use gnaw_core::tokenizer::TokenFormat;

    match format {
        TokenFormat::Raw => num.to_string(),
        TokenFormat::Format => {
            let s = num.to_string();
            let chars: Vec<char> = s.chars().collect();
            let mut result = String::new();

            for (i, c) in chars.iter().enumerate() {
                if i > 0 && (chars.len() - i).is_multiple_of(3) {
                    result.push(',');
                }
                result.push(*c);
            }
            result
        }
    }
}

/// Save template to custom directory
pub fn save_template_to_custom_dir(filename: &Path, content: &str) -> Result<()> {
    let templates_dir = if let Some(cfg) = dirs::config_dir() {
        cfg.join("gnaw").join("templates")
    } else {
        // Fallback to current directory if config_dir not available
        std::env::current_dir()?.join("templates")
    };

    std::fs::create_dir_all(&templates_dir)?;
    let full_path = templates_dir.join(filename);
    std::fs::write(full_path, content)?;
    Ok(())
}

/// Find custom templates and return (display_name, absolute_path).
pub fn load_all_templates() -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();

    // Candidate roots
    let mut roots = Vec::new();
    roots.push(std::env::current_dir()?.join("templates"));
    if let Some(cfg) = dirs::config_dir() {
        roots.push(cfg.join("gnaw").join("templates"));
    }

    // Accept common template extensions
    let is_template = |p: &Path| {
        matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("hbs") | Some("handlebars") | Some("md") | Some("tmpl")
        )
    };

    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&root).min_depth(1).max_depth(2) {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() && is_template(p) {
                let name = p
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("template")
                    .to_string();
                out.push((
                    name,
                    p.canonicalize()
                        .unwrap_or_else(|_| p.to_path_buf())
                        .to_string_lossy()
                        .into(),
                ));
            }
        }
    }

    // De-duplicate (same path could appear twice)
    // Let the compiler infer tuple types for the sort closure.
    out.sort_by(|a: &(String, String), b: &(String, String)| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    out.dedup_by(|a, b| a.1 == b.1);

    Ok(out)
}

/// Ensure a path exists in the file tree by creating missing intermediate nodes
pub fn ensure_path_exists_in_tree(
    root_nodes: &mut Vec<DisplayFileNode>,
    target_path: &Path,
    session: &mut SelectionState,
) -> Result<()> {
    let root_path = &session.config.path;

    // Get relative path components
    let relative_path = if let Ok(rel) = target_path.strip_prefix(root_path) {
        rel
    } else {
        return Ok(()); // Path is not under root, nothing to do
    };

    let components: Vec<_> = relative_path.components().collect();
    if components.is_empty() {
        return Ok(());
    }

    // Build path incrementally
    let mut current_path = root_path.to_path_buf();
    let mut current_nodes = root_nodes;

    for (level, component) in components.into_iter().enumerate() {
        current_path.push(component);

        // Find or create node at this level
        let node_name = component.as_os_str().to_string_lossy().to_string();

        // Look for existing node
        let existing_index = current_nodes.iter().position(|n| n.name == node_name);

        if let Some(index) = existing_index {
            // Node exists, ensure it's loaded if it's a directory
            let node = &mut current_nodes[index];
            if node.is_directory && !node.children_loaded {
                let _ = node.load_children(session);
            }
            current_nodes = &mut current_nodes[index].children;
        } else {
            // Node doesn't exist, create it
            let mut new_node = DisplayFileNode::new(current_path.clone(), level);

            if new_node.is_directory {
                let _ = new_node.load_children(session);
            }

            current_nodes.push(new_node);

            // Sort to maintain order
            current_nodes.sort_by(|a, b| match (a.is_directory, b.is_directory) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            });

            // Find the newly inserted node
            let new_index = current_nodes
                .iter()
                .position(|n| n.name == node_name)
                .unwrap();
            current_nodes = &mut current_nodes[new_index].children;
        }
    }

    Ok(())
}

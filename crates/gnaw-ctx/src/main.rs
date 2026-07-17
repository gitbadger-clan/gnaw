//! gnaw is a command-line tool to generate an LLM prompt from a codebase directory.
//!
//! Authors: Olivier D'Ancona (@ODAncona), Mufeed VH (@mufeedvh)
mod args;
mod banner;
mod clipboard;
mod config;
mod config_loader;
mod model;
mod pipeline_spec;
mod prompt;
mod token_map;
mod tui;
mod utils;
mod view;
mod widgets;

use crate::prompt::RenderedPrompt;
use crate::utils::format_number;
use anyhow::{Context, Result};
use args::Cli;
use clap::{CommandFactory, FromArgMatches};
use clap_complete::CompleteEnv;
use colored::*;
use gnaw_core::{template::write_to_file, tokenizer::TokenizerType};
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info};
use std::io::{IsTerminal, Write};
use std::path::Path;
use tui::run_tui;

#[tokio::main]
async fn main() -> Result<()> {
    CompleteEnv::with_factory(Cli::command)
        .bin("gnaw")
        .complete(); // first line; see prior note

    let matches = Cli::command().get_matches();
    let args = Cli::from_arg_matches(&matches)?;

    let path_explicit =
        matches.value_source("path") == Some(clap::parser::ValueSource::CommandLine);
    let stdin_is_pipe = !std::io::stdin().is_terminal();
    let use_stdin = stdin_is_pipe && !path_explicit && !args.tui && !args.clipboard_daemon;
    // Honor RUST_LOG as before; --timing additionally turns on the per-stage
    // breakdown so you don't need an env var to see it.
    let mut log_builder = env_logger::Builder::from_default_env();
    if args.timing {
        log_builder.filter(Some("gnaw::timing"), log::LevelFilter::Debug);
    }
    log_builder.init();

    info! {"Args: {:?}", std::env::args().collect::<Vec<_>>()};
    // ~~~ Clipboard Daemon ~~~
    #[cfg(target_os = "linux")]
    {
        use clipboard::serve_clipboard_daemon;
        if args.clipboard_daemon {
            info! {"Serving clipboard daemon..."};
            serve_clipboard_daemon()?;
            info! {"Shutting down gracefully..."};
            return Ok(());
        }
    }

    // Bare `gnaw`, interactive terminal, no args → show help. We removed
    // arg_required_else_help so an arg-less *piped* invocation reads stdin
    // instead of printing help. This runs AFTER the clipboard-daemon block so
    // it never steals the daemon's stdin.
    if !path_explicit && !stdin_is_pipe && std::env::args().len() == 1 {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    // Slurp piped stdin once, RAW, at the frontend edge. Whether it's a path
    // list or content is decided by classify_stdin AFTER config loads —
    // classification resolves lines against the root, and the root can come
    // from a config file, which build_session hasn't read yet at this point.
    let stdin_raw: Option<String> = if use_stdin {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading piped stdin")?;
        Some(buf)
    } else {
        None
    };

    // ~~~ TUI or CLI Mode ~~~
    if args.tui {
        let session = config::build_session(None, &args, args.tui).unwrap_or_else(|e| {
            error!("Failed to create session: {}", e);
            std::process::exit(1);
        });
        run_tui(session).await
    } else {
        let timing = args.timing;
        let started = timing.then(std::time::Instant::now);
        let res = run_cli_mode_with_args(args, stdin_raw).await;
        if let Some(t) = started {
            let secs = t.elapsed().as_secs_f64();
            if secs < 1.0 {
                eprintln!("Took {:.0}ms", secs * 1000.0);
            } else {
                eprintln!("Took {:.2}s", secs);
            }
        }
        res
    }
}

enum StdinMode {
    Paths(Vec<String>),
    Content(String),
}

fn classify_stdin(raw: String, root: &Path) -> StdinMode {
    // Sniff-only cap: content can be megabytes and we only need a signal.
    // ANY resolving line → path list. This deliberately protects the documented
    // `git diff --name-only` workflow where most listed files may be deleted
    // (they're dropped downstream, as the stdin-paths reference specifies);
    // genuine content (PEM, logs, diffs) resolves zero lines. Force-modes
    // (`-` for content, --stdin-paths for lists) cover the pathological rest.
    let any_file = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(1000)
        .any(|l| root.join(l).is_file());
    if any_file {
        StdinMode::Paths(
            raw.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect(), // FULL list — the cap was only for sniffing
        )
    } else {
        StdinMode::Content(raw)
    }
}

/// Run the CLI mode with parsed arguments
async fn run_cli_mode_with_args(args: Cli, stdin_raw: Option<String>) -> Result<()> {
    use config_loader::{get_default_output_destination, load_config};
    use gnaw_core::configuration::OutputDestination;

    let quiet_mode = args.quiet;

    // ~~~ Load Configuration ~~~
    let config_source = load_config(quiet_mode)?; // load config files first (local > global), then apply CLI args on top

    // ~~~ Build Session with config + CLI args ~~~
    // `mut` so we can attach the stdin path list onto the config below; the
    // pipeline's source selection reads `config.stdin_paths` to decide whether
    // to source the piped files instead of walking the tree.
    let mut session = config::build_session(Some(&config_source), &args, false)?;
    if let Some(raw) = stdin_raw {
        match classify_stdin(raw, &session.config.path) {
            StdinMode::Paths(p) => {
                info!("stdin: treated as path list");
                session.config.stdin_paths = Some(p);
            }
            StdinMode::Content(c) => {
                info!("stdin: treated as content (no lines resolved as files)");
                session.config.stdin_content = Some(c);
            }
        }
    }

    // Precompile the gitleaks ruleset up-front ONLY when we'll actually scan, so
    // `--secret-scan off` doesn't pay the ~0.4s compile it will never use.
    if session.config.secret_scan != gnaw_core::secret_scan::SecretPolicy::Off {
        // Transport the resolved DFA-cache size across the Lazy<GitleaksScanner>
        // boundary BEFORE warm() triggers the first compile. 0 is a no-op in the
        // setter, so an unset flag falls through to GNAW_DFA_MB / the default.
        gnaw_core::secret_scan::set_dfa_cache_mb(session.config.dfa_cache_mb);
        gnaw_core::secret_scan::warm();
    }
    // ~~~ Determine Output Behavior ~~~
    let default_output = get_default_output_destination(&config_source);

    // Determine final output destinations (Solution B: Unix-style behavior)
    let output_to_clipboard = if args.clipboard {
        // Explicit clipboard flag - ONLY clipboard, no stdout
        true
    } else if args.output_file.is_some() {
        // Output file specified, don't use clipboard unless explicitly requested
        false
    } else {
        // Use config default
        matches!(default_output, OutputDestination::Clipboard)
    };

    let output_to_stdout = if args.clipboard {
        false
    } else if let Some(ref output_file) = args.output_file {
        output_file == "-"
    } else {
        match default_output {
            OutputDestination::Stdout => true,
            OutputDestination::Clipboard => false,
            OutputDestination::File => false,
        }
    };

    if !output_to_stdout {
        banner::print_cli(quiet_mode);
    }

    // ~~~ Create Session ~~~
    let spinner = if !quiet_mode {
        Some(setup_spinner("Traversing directory and building tree..."))
    } else {
        None
    };

    let (rendered, token_map_files, split_data): (
        RenderedPrompt,
        Vec<crate::token_map::TokenMapFile>,
        Option<SplitData>,
    ) = {
        if let Some(s) = spinner.as_ref() {
            s.set_message("Proceeding…")
        }
        let r = crate::pipeline_spec::run_extraction(&session.config)?;

        // Capture before token_map_files / split_data may move r.chunks.
        let chunks_empty = r.chunks.is_empty();

        if session.config.secret_scan == gnaw_core::secret_scan::SecretPolicy::Block
            && !r.findings.is_empty()
        {
            if let Some(s) = spinner.as_ref() {
                s.finish_with_message("Blocked!".red().to_string());
            }
            let detail: Vec<String> = r
                .findings
                .iter()
                .map(|f| format!("{}:{} [{}]", f.path, f.line, f.rule_id))
                .collect();
            anyhow::bail!(
                "secret scan: {} finding(s) with --secret-scan=block; aborting\n  {}",
                r.findings.len(),
                detail.join("\n  ")
            );
        }

        let token_map_files = if args.token_map {
            r.chunks
                .iter()
                .map(|c| crate::token_map::TokenMapFile {
                    path: c.source_path.clone(),
                    tokens: c.tokens,
                })
                .collect()
        } else {
            Vec::new()
        };

        // Move chunks + tree out for split (only when requested). token_map's
        // borrow above has ended, so the move is fine even with both flags set.
        let split_data = if args.split_size.is_some() {
            Some(SplitData {
                chunks: r.chunks,
                source_tree: r.source_tree,
                encoding: r.tally.encoding,
            })
        } else {
            None
        };

        // Chrome-only runs (commit/changeset/PR) carry no content chunks, so the
        // budgeter tally is 0 — the payload is the rendered diff/log. Count the
        // body directly there; it's small, so this doesn't reintroduce the
        // full-body tokenize cost the chunk-sum avoids on large whole-repo runs
        // (which keep non-empty chunks and stay on the tally fast path).
        let token_count = if chunks_empty {
            gnaw_core::tokenizer::count_tokens(&r.body, &session.config.encoding)
        } else {
            r.tally.total
        };
        let rendered = RenderedPrompt {
            prompt: r.body,
            token_count,
            model_info: r.tally.model_info(),
            secret_findings: r.findings,
        };
        (rendered, token_map_files, split_data)
    };

    if let Some(ref s) = spinner {
        s.finish_with_message("Codebase Traversal Done!".green().to_string());
    }

    // ~~~ Token Count ~~~
    let token_count = rendered.token_count;
    let formatted_token_count = format_number(token_count, &session.config.token_format);
    let model_info = rendered.model_info;

    if !quiet_mode {
        eprintln!(
            "{}{}{} Token count: {}, Model info: {}",
            "[".bold().white(),
            "i".bold().blue(),
            "]".bold().white(),
            formatted_token_count,
            model_info
        );
    }

    if !rendered.secret_findings.is_empty() {
        eprintln!(
            "{}{}{} {}",
            "[".bold().white(),
            "!".bold().yellow(),
            "]".bold().white(),
            format!(
                "secret scan: {} potential secret(s)",
                rendered.secret_findings.len()
            )
            .yellow()
        );
        for f in &rendered.secret_findings {
            eprintln!(
                "    {}:{}  [{}]  {}  (entropy {:.1})",
                f.path, f.line, f.rule_id, f.preview, f.entropy
            );
        }
    }

    // ~~~ Token Map Display ~~~
    if args.token_map {
        use crate::token_map::{TokenMapEntry, display_token_map, generate_token_map_with_limit};

        if !token_map_files.is_empty() {
            // Content-only total — sum of per-file tokens. Matches the legacy map,
            // whose percentages were always file-content-only (not the structural
            // grand total). Both cfg paths fill token_map_files upstream, already
            // re-rooted, so this block no longer reads session.data or strips paths.
            let total_from_files: usize = token_map_files.iter().map(|f| f.tokens).sum();

            let max_lines: usize = args.token_map_lines.unwrap_or_else(|| {
                terminal_size::terminal_size()
                    .map(|(_, terminal_size::Height(h))| (h as usize).saturating_sub(10).max(20))
                    .unwrap_or(40)
            });

            let entries: Vec<TokenMapEntry> = generate_token_map_with_limit(
                &token_map_files,
                total_from_files,
                Some(max_lines),
                args.token_map_min_percent,
            );
            display_token_map(&entries, total_from_files);
        }
    }

    // ~~~ Output to Stdout ~~~
    if output_to_stdout {
        print!("{}", rendered.prompt);
        std::io::stdout()
            .flush()
            .context("Failed to flush stdout")?;
    }

    // ~~~ Copy to Clipboard ~~~
    if output_to_clipboard {
        use crate::clipboard::copy_to_clipboard;
        match copy_to_clipboard(&rendered.prompt) {
            Ok(_) => {
                if !quiet_mode {
                    eprintln!(
                        "{}{}{} {}",
                        "[".bold().white(),
                        "✓".bold().green(),
                        "]".bold().white(),
                        "Copied to clipboard successfully.".green()
                    );
                }
            }
            Err(e) => {
                if !quiet_mode {
                    eprintln!(
                        "{}{}{} {}",
                        "[".bold().white(),
                        "!".bold().red(),
                        "]".bold().white(),
                        format!("Failed to copy to clipboard: {}", e).red()
                    );
                }
            }
        }
    }

    // ~~~ Split Output ~~~
    if let Some(budget) = args.split_size {
        let base = args
            .output_file
            .as_deref()
            .filter(|f| *f != "-")
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--split-size requires --output-file as a base name \
                 (e.g. -O ctx.md); it cannot write to stdout or the clipboard"
                )
            })?;
        let split = split_data.expect("--split-size set ⇒ split_data populated");
        return write_split_output(&session.config, split, base, budget, quiet_mode);
    }

    // ~~~ Output File ~~~
    if let Some(ref output_file) = args.output_file
        && output_file != "-"
    {
        output_prompt(
            Some(std::path::Path::new(output_file)),
            &rendered.prompt,
            quiet_mode,
        )?;
    }

    Ok(())
}

/// Sets up a progress spinner with a given message
///
/// # Arguments
///
/// * `message` - A message to display with the spinner
///
/// # Returns
///
/// * `ProgressBar` - The configured progress spinner
fn setup_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.enable_steady_tick(std::time::Duration::from_millis(220));
    let done_symbol = format!(
        "{}{}{}",
        "[".bold().white(),
        "✓".bold().green(),
        "]".bold().white()
    );
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "▹▹▹▹▹",
                "▸▹▹▹▹",
                "▹▸▹▹▹",
                "▹▹▸▹▹",
                "▹▹▹▸▹",
                "▹▹▹▹▸",
                &done_symbol,
            ])
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    spinner.set_message(message.to_string());
    spinner
}

// ~~~ Output to file or stdout ~~~
fn output_prompt(
    effective_output: Option<&std::path::Path>,
    rendered: &str,
    quiet: bool,
) -> Result<()> {
    let output_path = match effective_output {
        Some(path) => path,
        None => return Ok(()), // nothing to do
    };

    let path_str = output_path.to_string_lossy();
    if path_str == "-" {
        // stdout
        print!("{}", rendered);
        std::io::stdout()
            .flush()
            .context("Failed to flush stdout")?;
    } else {
        // file
        write_to_file(&path_str, rendered)
            .context(format!("Failed to write to file: {}", path_str))?;

        if !quiet {
            eprintln!(
                "{}{}{} {}",
                "[".bold().white(),
                "✓".bold().green(),
                "]".bold().white(),
                format!("Prompt written to file: {}", path_str).green()
            );
        }
    }

    Ok(())
}

/// A group of files destined for one output part, plus its summed token count.
struct FilePart {
    indices: Vec<usize>,
    token_count: usize,
}

/// Pipeline-only split inputs, surfaced from the single extraction so split
/// reuses that one walk. Built only when --split-size is set.
struct SplitData {
    chunks: Vec<gnaw_core::pipeline::Chunk>,
    source_tree: String,
    encoding: TokenizerType,
}

/// Greedily packs files (in their existing, sorted order) into parts so that
/// each part's summed token count stays at or below `budget`.
///
/// Order is preserved (determinism). A single file whose own token_count
/// exceeds `budget` is placed alone in its own part; the caller is expected
/// to warn, since we never drop or truncate content.
fn group_files_by_budget(token_counts: &[usize], budget: usize) -> Vec<FilePart> {
    // A zero/again-degenerate budget would loop forever or produce one file
    // per part with no progress guarantee; treat <=0 as "everything in one part".
    if budget == 0 {
        return vec![FilePart {
            indices: (0..token_counts.len()).collect(),
            token_count: token_counts.iter().sum(),
        }];
    }

    let mut parts: Vec<FilePart> = Vec::new();
    let mut current = FilePart {
        indices: Vec::new(),
        token_count: 0,
    };

    for (idx, &tokens) in token_counts.iter().enumerate() {
        let would_overflow = current.token_count + tokens > budget;
        // Flush the current part before starting a new one, but only if it
        // actually holds something — avoids emitting an empty leading part
        // when the very first file already exceeds the budget.
        if would_overflow && !current.indices.is_empty() {
            parts.push(std::mem::replace(
                &mut current,
                FilePart {
                    indices: Vec::new(),
                    token_count: 0,
                },
            ));
        }
        current.indices.push(idx);
        current.token_count += tokens;
    }

    if !current.indices.is_empty() {
        parts.push(current);
    }
    parts
}

/// Pipeline split: pack already-extracted chunks by token budget and render each
/// part via `render_subset`, reusing the one source tree. No re-walk, no
/// re-tokenize — the single extraction produced chunks (already counted) and the
/// tree. Replaces the session-data path; that legacy sibling dies at Step 6.
fn write_split_output(
    config: &gnaw_core::configuration::GnawConfig,
    split: SplitData,
    base_path: &str,
    budget: usize,
    quiet: bool,
) -> Result<()> {
    use gnaw_core::pipeline::{Chunk, render_subset};

    let SplitData {
        chunks,
        source_tree,
        encoding,
    } = split;

    if chunks.is_empty() {
        anyhow::bail!("Nothing to split: no files were selected");
    }

    let token_counts: Vec<usize> = chunks.iter().map(|c| c.tokens).collect();
    let parts = group_files_by_budget(&token_counts, budget);

    let (stem, ext) = split_base_path(base_path);
    let total_parts = parts.len();

    // One renderer, matching whichever extraction produced these chunks.
    let renderer = crate::pipeline_spec::build_renderer_for(config)?;
    let root_label = gnaw_core::path::display_name(&config.path);

    // Relocate each chunk out by index exactly once (never cloned).
    let mut slots: Vec<Option<Chunk>> = chunks.into_iter().map(Some).collect();

    for (part_no, part) in parts.iter().enumerate() {
        let part_chunks: Vec<Chunk> = part
            .indices
            .iter()
            .map(|&i| {
                slots[i]
                    .take()
                    .expect("each index appears in exactly one part")
            })
            .collect();

        if part.token_count > budget && part_chunks.len() == 1 && !quiet {
            eprintln!(
                "{}{}{} {}",
                "[".bold().white(),
                "!".bold().yellow(),
                "]".bold().white(),
                format!(
                    "File '{}' alone is {} tokens, over the {}-token budget; \
                     it gets its own part.",
                    part_chunks[0].source_path, part.token_count, budget
                )
                .yellow()
            );
        }

        let rendered =
            render_subset(&renderer, &source_tree, &root_label, part_chunks, encoding)
                .map_err(|e| anyhow::anyhow!("Failed to render part {}: {}", part_no + 1, e))?;

        let part_path = format!("{}.part{}{}", stem, part_no + 1, ext);
        gnaw_core::template::write_to_file(&part_path, &rendered.body)
            .context(format!("Failed to write part file: {}", part_path))?;

        if !quiet {
            eprintln!(
                "{}{}{} {}",
                "[".bold().white(),
                "✓".bold().green(),
                "]".bold().white(),
                format!(
                    "Part {}/{} -> {} ({} tokens)",
                    part_no + 1,
                    total_parts,
                    part_path,
                    rendered.tally.total
                )
                .green()
            );
        }
    }

    Ok(())
}

/// Splits "ctx.md" into ("ctx", ".md") and "ctx" into ("ctx", "").
/// Splits on the final dot of the file name only, leaving directory
/// components untouched so "out/ctx.md" -> ("out/ctx", ".md").
fn split_base_path(base: &str) -> (String, String) {
    match std::path::Path::new(base).extension() {
        Some(ext) => {
            let ext = ext.to_string_lossy();
            let stem_len = base.len() - ext.len() - 1; // -1 for the dot
            (base[..stem_len].to_string(), format!(".{}", ext))
        }
        None => (base.to_string(), String::new()),
    }
}

#[cfg(test)]
mod split_tests {
    use super::{group_files_by_budget, split_base_path};

    #[test]
    fn packs_files_under_budget() {
        let parts = group_files_by_budget(&[40, 40, 40], 100);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].indices, vec![0, 1]); // 80 <= 100
        assert_eq!(parts[1].indices, vec![2]);
    }

    #[test]
    fn never_exceeds_budget_when_files_fit() {
        let counts = [30usize, 30, 30, 30, 30];
        let budget = 60;
        for part in group_files_by_budget(&counts, budget) {
            assert!(part.token_count <= budget, "part exceeded budget");
        }
    }

    #[test]
    fn oversized_single_file_gets_own_part() {
        let parts = group_files_by_budget(&[10, 500, 10], 100);
        // 10 | 500(alone) | 10
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].indices, vec![1]);
        assert!(parts[1].token_count > 100);
    }

    #[test]
    fn no_empty_leading_part_when_first_file_oversized() {
        let parts = group_files_by_budget(&[500, 10], 100);
        assert_eq!(parts.len(), 2);
        assert!(!parts[0].indices.is_empty());
    }

    #[test]
    fn every_index_appears_exactly_once() {
        let counts = [10usize, 90, 5, 200, 1];
        let parts = group_files_by_budget(&counts, 100);
        let mut seen: Vec<usize> = parts.iter().flat_map(|p| p.indices.clone()).collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..counts.len()).collect::<Vec<_>>());
    }

    #[test]
    fn zero_budget_collapses_to_single_part() {
        let parts = group_files_by_budget(&[10, 20, 30], 0);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].token_count, 60);
    }

    #[test]
    fn base_path_splitting() {
        assert_eq!(split_base_path("ctx.md"), ("ctx".into(), ".md".into()));
        assert_eq!(
            split_base_path("out/ctx.md"),
            ("out/ctx".into(), ".md".into())
        );
        assert_eq!(split_base_path("ctx"), ("ctx".into(), "".into()));
    }
}

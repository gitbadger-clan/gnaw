//! Terminal User Interface implementation.
//!
//! This module implements the complete TUI for gnaw using ratatui and crossterm.
//! It provides a tabbed interface with file selection, settings configuration,
//! statistics viewing, and prompt output. The interface supports keyboard navigation,
//! file tree browsing, real-time analysis, and clipboard integration.

use anyhow::Result;
use crossterm::{
    event::{Event, EventStream, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use gnaw_core::session::SelectionState;
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    prelude::*,
    widgets::*,
};
use std::io::{Stdout, stdout};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use crate::clipboard::copy_to_clipboard;
use crate::model::{
    AnalysisResults, AppMode, Cmd, FileTreeInputMode, Message, Model, StatisticsView, Tab,
    TemplateState,
    template::{FocusMode, TemplateFocus, VariableCategory},
};
use crate::token_map::{TokenMapFile, generate_token_map_with_limit};
use crate::utils::{save_template_to_custom_dir, save_to_file};
use crate::widgets::{
    FileSelectionWidget, OutputWidget, SettingsWidget, StatisticsByExtensionWidget,
    StatisticsOverviewWidget, StatisticsTokenMapWidget, TemplateWidget,
};
use gnaw_adapters::ExplicitSelector;
use gnaw_core::pipeline::{SourceOpts, run};

use crate::utils::stream_file_tree;
/// Quiet window after the last selection before a count batch fires.
const TOKEN_DEBOUNCE_MS: u64 = 200;
/// Which scroll family a message belongs to (for coalescing), or None if it's
/// not a coalescable scroll.
fn coalesce_key(m: &Message) -> Option<u8> {
    match m {
        Message::MoveTreeCursor(_) => Some(0),
        Message::ScrollOutput(_) => Some(1),
        Message::ScrollStatistics(_) => Some(2),
        _ => None,
    }
}

/// Sum two same-family scroll messages into one. Assumes same variant (checked
/// by the caller via coalesce_key equality).
fn merge_scroll(a: Message, b: Message) -> Message {
    match (a, b) {
        (Message::MoveTreeCursor(x), Message::MoveTreeCursor(y)) => Message::MoveTreeCursor(x + y),
        (Message::ScrollOutput(x), Message::ScrollOutput(y)) => Message::ScrollOutput(x + y),
        (Message::ScrollStatistics(x), Message::ScrollStatistics(y)) => {
            Message::ScrollStatistics(x + y)
        }
        // caller guarantees same family; unreachable, but return the newer as a safe fallback
        (_, b) => b,
    }
}
pub struct TuiApp {
    model: Model,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    message_tx: mpsc::UnboundedSender<Message>,
    message_rx: mpsc::UnboundedReceiver<Message>,
}

impl TuiApp {
    /// Create a new TUI application.
    ///
    /// Initializes the terminal and sets up the application state from the provided session.
    /// The initial file tree is requested via a `RefreshFileTree` message in `run()`.
    ///
    /// Returns an error if the terminal cannot be initialized.
    pub fn new(session: SelectionState) -> Result<Self> {
        let terminal = init_terminal()?;
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        let model = Model::new(session);

        Ok(Self {
            model,
            terminal,
            message_tx,
            message_rx,
        })
    }

    // ~~~ Optimized Main Loop ~~~
    // ~~~ Optimized Main Loop ~~~
    pub async fn run(&mut self) -> Result<()> {
        // Paint the shell immediately so the alt-screen isn't blank while we walk
        // the tree. file_tree_nodes is empty here; the FileTree widget renders an
        // empty list, which is fine — the status bar carries the "why".
        self.model.status_message = "Scanning repository…".to_string();
        {
            let Self {
                terminal, model, ..
            } = self;
            terminal.draw(|frame| TuiApp::render_with_model(model, frame))?;
        }
        self.handle_message(Message::RefreshFileTree)?;

        let mut events = EventStream::new();

        loop {
            // Copy the animation flag out first so the select! guard doesn't
            // borrow self while the message_rx branch borrows it mutably.
            let animating = self.model.prompt_output.analysis_in_progress;

            tokio::select! {
                // Branch 1: next terminal event. events.next() lives ONLY here,
                // in the select. Do NOT poll it opportunistically elsewhere:
                // the old burst-drain called events.next().now_or_never() and
                // dropped the future while pending, which desyncs crossterm's
                // reader-thread protocol and permanently stops terminal reads
                // (the first-keypress freeze). select!'s own cancellation of a
                // pending next() across iterations is the supported usage;
                // mid-poll drop from now_or_never was not.
                maybe_event = events.next() => {
                    match maybe_event {
                        Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                            let ratatui_key = self.convert_crossterm_key(key);
                            if let Some(message) = self.handle_key_event(ratatui_key) {
                                self.handle_message(message)?;
                            }
                        }
                        Some(Ok(_)) => {}          // resize, mouse, release — ignored
                        Some(Err(e)) => return Err(e.into()),
                        None => break,             // stream ended
                    }
                }

                // Branch 2: next internal message (analysis result, progress,
                // streamed token counts). recv() borrows &mut self.message_rx.
                // None = all senders dropped (tasks gone); nothing to do.
                maybe_msg = self.message_rx.recv() => {
                    if let Some(message) = maybe_msg {
                        // Coalesce a bounded batch. Consecutive scroll deltas
                        // (MoveTreeCursor/ScrollOutput/ScrollStatistics) commute —
                        // N steps == one N-sized step — so we sum them and apply
                        // once. Any non-scroll message flushes the accumulated
                        // scroll and is then handled normally: a newer action
                        // supersedes a backlog of scrolls instead of waiting
                        // behind it (the "scroll runs on" feel when you stop).
                        let mut pending_scroll: Option<Message> = None;
                        let mut budget = 64;

                        let feed = |this: &mut Self, msg: Message, pending: &mut Option<Message>| -> Result<()> {
                            match (coalesce_key(&msg), pending.take()) {
                                // same scroll kind as what's pending → merge deltas
                                (Some(k), Some(prev)) if coalesce_key(&prev) == Some(k) => {
                                    *pending = Some(merge_scroll(prev, msg));
                                }
                                // a scroll, but different kind pending → flush old, hold new
                                (Some(_), Some(prev)) => {
                                    this.handle_message(prev)?;
                                    *pending = Some(msg);
                                }
                                // a scroll, nothing pending → hold it
                                (Some(_), None) => {
                                    *pending = Some(msg);
                                }
                                // not a scroll → flush any pending scroll, then handle this
                                (None, prev) => {
                                    if let Some(prev) = prev {
                                        this.handle_message(prev)?;
                                    }
                                    this.handle_message(msg)?;
                                }
                            }
                            Ok(())
                        };

                        feed(self, message, &mut pending_scroll)?;
                        while budget > 0 {
                            match self.message_rx.try_recv() {
                                Ok(more) => { feed(self, more, &mut pending_scroll)?; budget -= 1; }
                                Err(_) => break,
                            }
                        }
                        // Flush whatever scroll is still accumulated.
                        if let Some(msg) = pending_scroll {
                            self.handle_message(msg)?;
                        }
                    }
                }

                // Branch 3: animation tick — ONLY armed while something is
                // spinning. When idle this branch is disabled, so the loop
                // truly sleeps (zero idle CPU) instead of waking at 60fps.
                _ = tokio::time::sleep(std::time::Duration::from_millis(80)), if animating => {}
            }

            let Self {
                terminal, model, ..
            } = self;
            terminal.draw(|frame| TuiApp::render_with_model(model, frame))?;

            if self.model.should_quit {
                break;
            }
        }

        Ok(())
    }

    /// Render the TUI using the provided model and frame.
    ///
    /// This function handles the layout and rendering of all components based on the current state.
    /// It divides the terminal into sections for the tab bar, content area, and status bar,
    /// and renders the appropriate widgets for the active tab.
    ///
    /// # Arguments
    ///
    /// * `model` - The current application state model
    /// * `frame` - The frame to render the UI components onto
    ///
    fn render_with_model(model: &Model, frame: &mut Frame) {
        let area = frame.area();

        // ~~~ Main layout ~~~
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Tab bar
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Status bar
            ])
            .split(area);

        // Tab bar
        Self::render_tab_bar_static(model, frame, main_layout[0]);

        // Current tab content
        match model.current_tab {
            Tab::FileTree => {
                let widget = FileSelectionWidget::new(model);
                let mut state = ();
                frame.render_stateful_widget(widget, main_layout[1], &mut state);
            }
            Tab::Settings => {
                let widget = SettingsWidget::new(model);
                let mut state = ();
                frame.render_stateful_widget(widget, main_layout[1], &mut state);
            }
            Tab::Statistics => match model.statistics.view {
                StatisticsView::Overview => {
                    let widget = StatisticsOverviewWidget::new(model);
                    frame.render_widget(widget, main_layout[1]);
                }
                StatisticsView::TokenMap => {
                    let widget = StatisticsTokenMapWidget::new(model);
                    let mut state = ();
                    frame.render_stateful_widget(widget, main_layout[1], &mut state);
                }
                StatisticsView::Extensions => {
                    let widget = StatisticsByExtensionWidget::new(model);
                    let mut state = ();
                    frame.render_stateful_widget(widget, main_layout[1], &mut state);
                }
            },
            Tab::Template => {
                let widget = TemplateWidget::new(model);
                let mut state = TemplateState::from_model(model);
                frame.render_stateful_widget(widget, main_layout[1], &mut state);
            }
            Tab::PromptOutput => {
                let widget = OutputWidget::new(model);
                let mut state = ();
                frame.render_stateful_widget(widget, main_layout[1], &mut state);
            }
        }

        // Status bar
        Self::render_status_bar_static(model, frame, main_layout[2]);
    }

    /// Handle a key event and return an optional message.
    ///
    /// This function processes keyboard input, prioritizing search mode
    /// when active. It handles global shortcuts for tab switching and quitting,
    /// as well as delegating tab-specific key events to the appropriate handlers.
    /// # Arguments
    ///
    /// * `key` - The key event to handle.
    ///
    /// # Returns
    ///
    /// * `Option<Message>` - An optional message to be processed by the main loop.
    ///   
    fn handle_key_event(&self, key: KeyEvent) -> Option<Message> {
        // Command line intercepts everything while open.
        if self.model.command_line.is_some() {
            return self.handle_command_keys(key);
        }
        // Check if we're in search mode first - this takes priority over global shortcuts
        if self.model.file_tree_input_mode == FileTreeInputMode::Search
            && self.model.current_tab == Tab::FileTree
        {
            return self.handle_file_tree_keys(key);
        }

        // Check if we're in template editing mode - ESC should exit editing mode, not quit app
        if self.model.current_tab == Tab::Template && self.model.template.is_in_editing_mode() {
            if key.code == KeyCode::Esc {
                return Some(Message::SetTemplateFocusMode(FocusMode::Normal));
            }
            // In editing modes, delegate to template handler
            return self.handle_template_keys(key);
        }

        // Global shortcuts (only when not in search mode or template editing mode)
        match key.code {
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Some(Message::Quit);
            }
            KeyCode::Char(':') => return Some(Message::EnterCommandMode),
            // Normal-mode Esc is a no-op now; quit moved to `:q`. Ctrl+Q kept as a hard escape hatch.
            KeyCode::Esc => return None,
            KeyCode::Char('1') => return Some(Message::SwitchTab(Tab::FileTree)),
            KeyCode::Char('2') => return Some(Message::SwitchTab(Tab::Settings)),
            KeyCode::Char('3') => return Some(Message::SwitchTab(Tab::Statistics)),
            KeyCode::Char('4') => return Some(Message::SwitchTab(Tab::Template)),
            KeyCode::Char('5') => return Some(Message::SwitchTab(Tab::PromptOutput)),
            KeyCode::Tab if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                // Cycle through tabs: Selection -> Settings -> Statistics -> Template -> Output -> Selection
                let next_tab = match self.model.current_tab {
                    Tab::FileTree => Tab::Settings,
                    Tab::Settings => Tab::Statistics,
                    Tab::Statistics => Tab::Template,
                    Tab::Template => Tab::PromptOutput,
                    Tab::PromptOutput => Tab::FileTree,
                };
                return Some(Message::SwitchTab(next_tab));
            }
            KeyCode::BackTab | KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                // Cycle through tabs in reverse: Selection <- Settings <- Statistics <- Template <- Output <- Selection
                let prev_tab = match self.model.current_tab {
                    Tab::FileTree => Tab::PromptOutput,
                    Tab::Settings => Tab::FileTree,
                    Tab::Statistics => Tab::Settings,
                    Tab::Template => Tab::Statistics,
                    Tab::PromptOutput => Tab::Template,
                };
                return Some(Message::SwitchTab(prev_tab));
            }
            _ => {}
        }

        // Tab-specific shortcuts
        match self.model.current_tab {
            Tab::FileTree => self.handle_file_tree_keys(key),
            Tab::Settings => self.handle_settings_keys(key),
            Tab::Statistics => self.handle_statistics_keys(key),
            Tab::Template => self.handle_template_keys(key),
            Tab::PromptOutput => self.handle_prompt_output_keys(key),
        }
    }

    fn handle_file_tree_keys(&self, key: KeyEvent) -> Option<Message> {
        // Pure logic in TUI - no direct widget calls (Elm/Redux pattern)
        if self.model.file_tree_input_mode == FileTreeInputMode::Search {
            match key.code {
                KeyCode::Esc => Some(Message::ExitSearchMode),
                KeyCode::Enter => {
                    // Apply search and exit search mode
                    Some(Message::ExitSearchMode)
                }
                KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    Some(Message::SearchHistoryPrev)
                }
                KeyCode::Backspace => {
                    let mut query = self.model.search_query.clone();
                    query.pop();
                    Some(Message::UpdateSearchQuery(query))
                }
                KeyCode::Char(c) => {
                    let mut query = self.model.search_query.clone();
                    query.push(c);
                    Some(Message::UpdateSearchQuery(query))
                }
                _ => None,
            }
        } else {
            // Normal navigation mode
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => Some(Message::MoveTreeCursor(-1)),
                KeyCode::Down | KeyCode::Char('j') => Some(Message::MoveTreeCursor(1)),
                KeyCode::PageUp => Some(Message::MoveTreeCursor(-10)),
                KeyCode::PageDown => Some(Message::MoveTreeCursor(10)),
                KeyCode::Home | KeyCode::Char('g') => Some(Message::MoveTreeCursor(-9999)),
                KeyCode::End | KeyCode::Char('G') => Some(Message::MoveTreeCursor(9999)),
                KeyCode::Char(' ') => Some(Message::ToggleFileSelection(self.model.tree_cursor)),
                KeyCode::Enter => Some(Message::RunAnalysis),
                KeyCode::Right | KeyCode::Char('l') => {
                    Some(Message::ExpandDirectory(self.model.tree_cursor))
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    Some(Message::CollapseDirectory(self.model.tree_cursor))
                }
                KeyCode::Char('/') => Some(Message::EnterSearchMode),
                KeyCode::Char('s') | KeyCode::Char('S') => Some(Message::EnterSearchMode),
                KeyCode::Char('a') => Some(Message::SelectMatches),
                KeyCode::Char('d') => Some(Message::DeselectMatches),
                KeyCode::Char('r') | KeyCode::Char('R') => Some(Message::RefreshFileTree),
                _ => None,
            }
        }
    }

    fn handle_settings_keys(&self, key: KeyEvent) -> Option<Message> {
        match key.code {
            KeyCode::Up => Some(Message::MoveSettingsCursor(-1)),
            KeyCode::Down => Some(Message::MoveSettingsCursor(1)),
            KeyCode::Char(' ') => Some(Message::ToggleSetting(self.model.settings.settings_cursor)),
            KeyCode::Left | KeyCode::Right => {
                Some(Message::CycleSetting(self.model.settings.settings_cursor))
            }
            KeyCode::Enter => Some(Message::RunAnalysis),
            _ => None,
        }
    }

    fn handle_statistics_keys(&self, key: KeyEvent) -> Option<Message> {
        match key.code {
            KeyCode::Enter => Some(Message::RunAnalysis),
            KeyCode::Left => Some(Message::CycleStatisticsView(-1)), // Previous view
            KeyCode::Right => Some(Message::CycleStatisticsView(1)), // Next view
            KeyCode::Up => Some(Message::ScrollStatistics(-1)),
            KeyCode::Down => Some(Message::ScrollStatistics(1)),
            KeyCode::PageUp => Some(Message::ScrollStatistics(-5)),
            KeyCode::PageDown => Some(Message::ScrollStatistics(5)),
            KeyCode::Home => Some(Message::ScrollStatistics(-9999)),
            KeyCode::End => Some(Message::ScrollStatistics(9999)),
            _ => None,
        }
    }

    fn handle_template_keys(&self, key: KeyEvent) -> Option<Message> {
        let is_in_editing_mode = self.model.template.is_in_editing_mode();
        let current_focus = self.model.template.get_focus();

        // Handle ESC key to exit editing modes
        if key.code == KeyCode::Esc && is_in_editing_mode {
            return Some(Message::SetTemplateFocusMode(FocusMode::Normal));
        }

        if is_in_editing_mode {
            match current_focus {
                TemplateFocus::Editor => {
                    return Some(Message::TemplateEditorInput(key));
                }
                TemplateFocus::Variables => {
                    if self.model.template.variables.is_editing() {
                        // Currently editing a variable value
                        match key.code {
                            KeyCode::Char(c) => return Some(Message::VariableInputChar(c)),
                            KeyCode::Backspace => return Some(Message::VariableInputBackspace),
                            KeyCode::Enter => return Some(Message::VariableInputEnter),
                            KeyCode::Esc => return Some(Message::VariableInputCancel),
                            _ => return None,
                        }
                    } else {
                        // Navigating variables list
                        match key.code {
                            KeyCode::Up => return Some(Message::VariableNavigateUp),
                            KeyCode::Down => return Some(Message::VariableNavigateDown),
                            KeyCode::Enter | KeyCode::Char(' ') => {
                                // Start editing the current variable
                                let variables = self.model.template.get_organized_variables();
                                if let Some(var) =
                                    variables.get(self.model.template.variables.cursor)
                                    && var.category == VariableCategory::Missing
                                {
                                    return Some(Message::VariableStartEditing(var.name.clone()));
                                }
                                return None;
                            }
                            _ => return None,
                        }
                    }
                }
                _ => {}
            }
        }

        // Normal mode: Handle global shortcuts and focus switching
        match key.code {
            KeyCode::Char('e') | KeyCode::Char('E') => {
                return Some(Message::SetTemplateFocus(
                    TemplateFocus::Editor,
                    FocusMode::EditingTemplate,
                ));
            }
            KeyCode::Char('v') | KeyCode::Char('V') => {
                return Some(Message::SetTemplateFocus(
                    TemplateFocus::Variables,
                    FocusMode::EditingVariable,
                ));
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                return Some(Message::SetTemplateFocus(
                    TemplateFocus::Picker,
                    FocusMode::Normal,
                ));
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                // Save template with timestamp
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let filename = format!("custom_template_{}", timestamp);
                return Some(Message::SaveTemplate(filename));
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                // Reload default template
                return Some(Message::ReloadTemplate);
            }
            KeyCode::Enter => {
                // Run analysis
                return Some(Message::RunAnalysis);
            }
            _ => {}
        }

        // Handle input for focused component in normal mode
        if current_focus == TemplateFocus::Picker {
            match key.code {
                KeyCode::Up => return Some(Message::TemplatePickerMove(-1)),
                KeyCode::Down => return Some(Message::TemplatePickerMove(1)),
                KeyCode::Enter | KeyCode::Char('l') | KeyCode::Char('L') | KeyCode::Char(' ') => {
                    return Some(Message::LoadTemplate);
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    return Some(Message::RefreshTemplates);
                }
                _ => {}
            }
        }

        None
    }

    fn handle_prompt_output_keys(&self, key: KeyEvent) -> Option<Message> {
        match key.code {
            KeyCode::Up => Some(Message::ScrollOutput(-1)),
            KeyCode::Down => Some(Message::ScrollOutput(1)),
            KeyCode::PageUp => Some(Message::ScrollOutput(-10)),
            KeyCode::PageDown => Some(Message::ScrollOutput(10)),
            KeyCode::Home => Some(Message::ScrollOutput(-9999)),
            KeyCode::End => Some(Message::ScrollOutput(9999)),
            KeyCode::Char('c') | KeyCode::Char('C') => Some(Message::CopyToClipboard),
            KeyCode::Char('s') | KeyCode::Char('S') => {
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let filename = format!("prompt_{}.md", timestamp);
                Some(Message::SaveToFile(filename))
            }
            KeyCode::Enter => Some(Message::RunAnalysis),
            _ => None,
        }
    }
    fn handle_command_keys(&self, key: KeyEvent) -> Option<Message> {
        match key.code {
            KeyCode::Esc => Some(Message::ExitCommandMode),
            KeyCode::Enter => Some(Message::ExecuteCommand),
            KeyCode::Backspace => Some(Message::CommandInputBackspace),
            KeyCode::Char(c) => Some(Message::CommandInputChar(c)),
            _ => None,
        }
    }
    /// Handle a message using the Elm/Redux pattern.
    /// This uses the pure Model::update() function and executes any side effects.
    fn handle_message(&mut self, message: Message) -> Result<()> {
        let cmd = self.model.update(message);

        // Execute any side effects
        self.execute_cmd(cmd)?;

        Ok(())
    }

    /// Execute a command (side effect) from the Model::update() function.
    /// This is where all the impure operations happen.
    fn execute_cmd(&mut self, cmd: Cmd) -> Result<()> {
        match cmd {
            Cmd::None => {
                // No side effect
            }

            Cmd::RefreshFileTree => {
                // Hand the walk to a worker; keep the main loop drawing. session needs to
                // be cheaply shareable into the task — clone the config/roots it needs, or
                // wrap in Arc. Don't move &mut self.model.session across the await.
                let tx = self.message_tx.clone();
                let session = self.model.session.clone(); // or Arc<…>, whichever is cheaper
                tokio::spawn(async move {
                    // build_file_tree_from_session is sync/CPU-bound → spawn_blocking so it
                    // doesn't stall a runtime worker that other tasks share.
                    let result = tokio::task::spawn_blocking(move || {
                        let mut session = session;
                        build_file_tree_from_session(&mut session)
                    })
                    .await;

                    match result {
                        Ok(Ok(tree)) => {
                            let _ = tx.send(Message::FileTreeReady(tree));
                            let _ = tx.send(Message::InitialTokenScan);
                        }
                        Ok(Err(e)) => {
                            let _ = tx.send(Message::FileTreeError(e.to_string()));
                        }
                        Err(join) => {
                            let _ = tx.send(Message::FileTreeError(join.to_string()));
                        }
                    }
                });
            }

            Cmd::RunAnalysis {
                template_content,
                user_variables,
            } => {
                // Build a one-shot config from the current session: the editor's
                // template plus the user's variable values. (Was: clone session,
                // mutate, call the now-deleted session.generate_prompt().)
                let mut config = self.model.session.config.clone();
                config.template_str = template_content;
                config.template_name = "Custom Template".to_string();
                config.user_variables = user_variables;

                // Snapshot the interactive selection. get_selected_files() returns
                // Result<Vec<PathBuf>> — unwrap it before mapping, surfacing a
                // selection error as an analysis error rather than panicking.
                let selected: Vec<String> = match self.model.session.get_selected_files() {
                    Ok(paths) => paths
                        .iter()
                        .map(|p| {
                            p.strip_prefix(&config.path)
                                .unwrap_or(p)
                                .to_string_lossy()
                                .into_owned()
                        })
                        .collect(),
                    Err(e) => {
                        let _ = self.message_tx.send(Message::AnalysisError(e.to_string()));
                        return Ok(()); // bail this Cmd; nothing to analyze
                    }
                };

                let tx = self.message_tx.clone();

                // Pipeline work (file reads + tokenization) is blocking, so run it
                // on the blocking pool rather than stalling an async worker — same
                // reason Cmd::CountTokens uses spawn_blocking.
                tokio::task::spawn_blocking(move || {
                    let analysis = (|| -> anyhow::Result<AnalysisResults> {
                        // build_spec picks WorkingTreeSource + IdentityChunker for a
                        // custom, non-diff run; swap its pattern selector for the
                        // explicit one built from the user's selection.
                        let mut spec = crate::pipeline_spec::build_spec(&config)?;
                        let ptx = tx.clone();
                        spec.progress = Some(Box::new(move |stage| {
                            let _ = ptx.send(Message::AnalysisProgress(stage));
                        }));
                        spec.selector = Box::new(ExplicitSelector::new(selected));

                        let r = run(&spec, &SourceOpts)?;

                        let token_count = r.tally.total;

                        // IdentityChunker emits one chunk per file, so chunks map
                        // 1:1 to files for both the count and the token map.
                        let map_files: Vec<TokenMapFile> = r
                            .chunks
                            .iter()
                            .map(|c| TokenMapFile {
                                path: c.source_path.clone(),
                                tokens: c.tokens,
                            })
                            .collect();

                        let token_map_entries = if token_count > 0 {
                            generate_token_map_with_limit(
                                &map_files,
                                token_count,
                                Some(50),
                                Some(0.5),
                            )
                        } else {
                            Vec::new()
                        };

                        Ok(AnalysisResults {
                            file_count: map_files.len(),
                            token_count: Some(token_count),
                            generated_prompt: r.body,
                            token_map_entries,
                        })
                    })();

                    match analysis {
                        Ok(result) => {
                            let _ = tx.send(Message::AnalysisComplete(result));
                        }
                        Err(e) => {
                            let _ = tx.send(Message::AnalysisError(e.to_string()));
                        }
                    }
                });
            }
            Cmd::ScheduleTokenCount(debounce_gen) => {
                // Sleep, then ask update to flush. If a newer selection bumped the
                // generation meanwhile, the flush arm sees gen != current and drops it.
                let tx = self.message_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(TOKEN_DEBOUNCE_MS)).await;
                    let _ = tx.send(Message::FlushTokenQueue(debounce_gen));
                });
            }

            Cmd::CountTokens { paths } => {
                let tx = self.message_tx.clone();
                let config = self.model.session.config.clone();

                tokio::task::spawn_blocking(move || {
                    use rayon::prelude::*;
                    // Parallel count on the rayon pool (the CLI counts at
                    // cpu×~7; serial here was the bulk of the TUI's startup
                    // gap on big repos). Chunked so per-file messages still
                    // stream for progressive UI fill without per-send churn.
                    paths.par_chunks(64).for_each(|chunk| {
                        for path in chunk {
                            let tokens = gnaw_adapters::path::count_file_tokens(path, &config);
                            let _ = tx.send(Message::TokenCounted {
                                path: path.clone(),
                                tokens,
                            });
                        }
                    });
                });
            }
            Cmd::CopyToClipboard(content) => match copy_to_clipboard(&content) {
                Ok(_) => {
                    self.model.status_message = "Copied to clipboard!".to_string();
                }
                Err(e) => {
                    self.model.status_message = format!("Copy failed: {}", e);
                }
            },

            Cmd::SaveToFile { filename, content } => {
                match save_to_file(std::path::Path::new(&filename), &content) {
                    Ok(_) => {
                        self.model.status_message = format!("Saved to {}", filename);
                    }
                    Err(e) => {
                        self.model.status_message = format!("Save failed: {}", e);
                    }
                }
            }

            Cmd::SaveTemplate { filename, content } => {
                match save_template_to_custom_dir(std::path::Path::new(&filename), &content) {
                    Ok(_) => {
                        self.model.status_message = format!("Template saved as {}", filename);
                        // Refresh templates to show the new one
                        self.model.template.picker.refresh();
                    }
                    Err(e) => {
                        self.model.status_message = format!("Template save failed: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn render_tab_bar_static(model: &Model, frame: &mut Frame, area: Rect) {
        let tabs = vec![
            "1. Selection",
            "2. Settings",
            "3. Statistics",
            "4. Template",
            "5. Output",
        ];
        let selected = match model.current_tab {
            Tab::FileTree => 0,
            Tab::Settings => 1,
            Tab::Statistics => 2,
            Tab::Template => 3,
            Tab::PromptOutput => 4,
        };

        let tabs_widget = Tabs::new(tabs)
            .block(Block::default().borders(Borders::ALL).title("Gnaw TUI"))
            .select(selected)
            .style(Style::default().fg(Color::White))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_widget(tabs_widget, area);
    }

    fn render_status_bar_static(model: &Model, frame: &mut Frame, area: Rect) {
        let (status_text, color) = match model.mode() {
            AppMode::Command => (
                format!(":{}", model.command_line.as_deref().unwrap_or("")),
                Color::Yellow,
            ),
            AppMode::Insert => (
                format!("-- INSERT --  {}", model.status_message),
                Color::Green,
            ),
            AppMode::Normal => {
                let text = if !model.status_message.is_empty() {
                    model.status_message.clone()
                } else {
                    let sort = match model.tree_sort_mode {
                        crate::model::TreeSortMode::Path => "path",
                        crate::model::TreeSortMode::TokenWeight => "tokens",
                    };
                    format!(":q Quit | :sort {sort} | 1-5 Tabs | Tab Switch | / Search")
                };
                (text, Color::Cyan)
            }
        };

        let status_widget = Paragraph::new(status_text)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(color));
        frame.render_widget(status_widget, area);
    }

    /// Convert crossterm KeyEvent to ratatui KeyEvent
    fn convert_crossterm_key(&self, key: crossterm::event::KeyEvent) -> KeyEvent {
        use ratatui::crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};

        KeyEvent {
            code: match key.code {
                crossterm::event::KeyCode::Backspace => KeyCode::Backspace,
                crossterm::event::KeyCode::Enter => KeyCode::Enter,
                crossterm::event::KeyCode::Left => KeyCode::Left,
                crossterm::event::KeyCode::Right => KeyCode::Right,
                crossterm::event::KeyCode::Up => KeyCode::Up,
                crossterm::event::KeyCode::Down => KeyCode::Down,
                crossterm::event::KeyCode::Home => KeyCode::Home,
                crossterm::event::KeyCode::End => KeyCode::End,
                crossterm::event::KeyCode::PageUp => KeyCode::PageUp,
                crossterm::event::KeyCode::PageDown => KeyCode::PageDown,
                crossterm::event::KeyCode::Tab => KeyCode::Tab,
                crossterm::event::KeyCode::BackTab => KeyCode::BackTab,
                crossterm::event::KeyCode::Delete => KeyCode::Delete,
                crossterm::event::KeyCode::Insert => KeyCode::Insert,
                crossterm::event::KeyCode::F(n) => KeyCode::F(n),
                crossterm::event::KeyCode::Char(c) => KeyCode::Char(c),
                crossterm::event::KeyCode::Null => KeyCode::Null,
                crossterm::event::KeyCode::Esc => KeyCode::Esc,
                _ => KeyCode::Null, // Simplified for other key codes
            },
            modifiers: KeyModifiers::from_bits_truncate(key.modifiers.bits()),
            kind: match key.kind {
                crossterm::event::KeyEventKind::Press => KeyEventKind::Press,
                crossterm::event::KeyEventKind::Repeat => KeyEventKind::Repeat,
                crossterm::event::KeyEventKind::Release => KeyEventKind::Release,
            },
            state: KeyEventState::from_bits_truncate(key.state.bits()),
        }
    }
}

/// Run the Terminal User Interface.
///
/// This is the main entry point for the TUI mode. It parses command-line arguments,
/// initializes the TUI application, and runs the main event loop until the user exits.
///
/// # Returns
///
/// * `Result<()>` - Ok on successful exit, Err if initialization or runtime errors occur
///
/// # Errors
///
/// Returns an error if the TUI cannot be initialized or if runtime errors occur during execution.
pub async fn run_tui(session: SelectionState) -> Result<()> {
    let mut app = TuiApp::new(session)?;

    let result = app.run().await;

    // Clean up terminal
    restore_terminal()?;

    result
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map_err(Into::into)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen)?;
    Ok(())
}

use crate::api::{
    ApiClient,
    models::{
        cache::CacheInspectResponse,
        workspace::{
            WorkspaceStatusMissedKey, WorkspaceStatusResponse, WorkspaceStatusSession,
            WorkspaceStatusTool, WorkspaceTagFeedItem, WorkspaceTagsResponse,
        },
    },
};
use crate::progress::format_bytes;
use anyhow::{Result, bail};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap},
};
use std::{
    io::{self, IsTerminal, Stdout},
    time::{Duration, Instant},
};

pub async fn execute(
    workspace_option: Option<String>,
    period: String,
    insight_limit: u32,
    tag_limit: u32,
    interval_seconds: u64,
) -> Result<()> {
    if !io::stdout().is_terminal() || std::env::var_os("CI").is_some() {
        bail!("Dashboard requires an interactive terminal.");
    }

    let mut app = DashboardApp::new(
        workspace_option,
        period,
        insight_limit,
        tag_limit,
        interval_seconds,
    )
    .await?;
    let (mut terminal, guard) = DashboardTerminalGuard::enter()?;
    let result = app.run(&mut terminal).await;
    drop(terminal);
    drop(guard);
    result
}

struct DashboardTerminalGuard;

impl DashboardTerminalGuard {
    fn enter() -> Result<(Terminal<CrosstermBackend<Stdout>>, Self)> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok((terminal, Self))
    }
}

impl Drop for DashboardTerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

struct DashboardApp {
    api_client: ApiClient,
    workspace: String,
    period: String,
    insight_limit: u32,
    tag_limit: u32,
    tag_page: u32,
    include_system_tags: bool,
    refresh_interval: Duration,
    side_panel: SidePanel,
    selected_tag: usize,
    status: WorkspaceStatusResponse,
    tags: WorkspaceTagsResponse,
    last_refresh: Instant,
    footer_message: Option<String>,
    inspect_modal: Option<InspectModal>,
}

#[derive(Copy, Clone)]
enum SidePanel {
    Sessions,
    Misses,
    Tools,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LayoutMode {
    Full,
    Compact,
    TooSmall,
}

impl SidePanel {
    fn index(self) -> usize {
        match self {
            Self::Sessions => 0,
            Self::Misses => 1,
            Self::Tools => 2,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Sessions => Self::Misses,
            Self::Misses => Self::Tools,
            Self::Tools => Self::Sessions,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Sessions => Self::Tools,
            Self::Misses => Self::Sessions,
            Self::Tools => Self::Misses,
        }
    }
}

enum InspectModal {
    Ready {
        tag: String,
        data: Box<CacheInspectResponse>,
    },
    Missing {
        tag: String,
    },
    Error {
        tag: String,
        message: String,
    },
}

impl DashboardApp {
    async fn new(
        workspace_option: Option<String>,
        period: String,
        insight_limit: u32,
        tag_limit: u32,
        interval_seconds: u64,
    ) -> Result<Self> {
        let api_client = ApiClient::for_restore()?;
        let workspace = crate::command_support::resolve_workspace(
            &api_client,
            workspace_option,
            "boringcache dashboard <workspace>",
        )
        .await?;
        let (status, tags) = fetch_dashboard_data(
            &api_client,
            &workspace,
            &period,
            insight_limit,
            tag_limit,
            1,
            false,
        )
        .await?;

        Ok(Self {
            api_client,
            workspace,
            period,
            insight_limit,
            tag_limit,
            tag_page: 1,
            include_system_tags: false,
            refresh_interval: Duration::from_secs(interval_seconds),
            side_panel: SidePanel::Sessions,
            selected_tag: 0,
            status,
            tags,
            last_refresh: Instant::now(),
            footer_message: None,
            inspect_modal: None,
        })
    }

    async fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(Duration::from_millis(250))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if self.handle_key(key).await? {
                            break;
                        }
                    }
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }

            if self.last_refresh.elapsed() >= self.refresh_interval {
                self.refresh_in_place().await;
            }
        }

        Ok(())
    }

    async fn handle_key(&mut self, key: KeyEvent) -> Result<bool> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(true);
        }

        if self.inspect_modal.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.inspect_modal = None;
                }
                _ => {}
            }
            return Ok(false);
        }

        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('r') => self.refresh_in_place().await,
            KeyCode::Down | KeyCode::Char('j') => self.select_next_tag(),
            KeyCode::Up | KeyCode::Char('k') => self.select_previous_tag(),
            KeyCode::Home | KeyCode::Char('g') => self.selected_tag = 0,
            KeyCode::End | KeyCode::Char('G') => {
                if !self.tags.tags.is_empty() {
                    self.selected_tag = self.tags.tags.len() - 1;
                }
            }
            KeyCode::PageDown | KeyCode::Char('n') => self.next_page().await,
            KeyCode::PageUp | KeyCode::Char('p') => self.previous_page().await,
            KeyCode::Char('s') => self.toggle_system_tags().await,
            KeyCode::Tab => self.side_panel = self.side_panel.next(),
            KeyCode::BackTab => self.side_panel = self.side_panel.previous(),
            KeyCode::Enter | KeyCode::Char('i') => self.open_selected_tag_inspect().await,
            _ => {}
        }

        Ok(false)
    }

    fn draw(&self, frame: &mut ratatui::Frame<'_>) {
        let area = frame.area();
        let attention_lines = attention_items(&self.status);

        match dashboard_layout_mode(area) {
            LayoutMode::TooSmall => self.draw_too_small(frame, area),
            LayoutMode::Full => {
                let attention_height = (attention_lines.len().min(4) as u16) + 2;
                let sections = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(4),
                        Constraint::Length(attention_height),
                        Constraint::Min(12),
                        Constraint::Length(3),
                    ])
                    .split(area);

                self.draw_header(frame, sections[0]);
                self.draw_attention(frame, sections[1], &attention_lines);
                self.draw_body(frame, sections[2]);
                self.draw_footer(frame, sections[3]);
            }
            LayoutMode::Compact => {
                let attention_height = (attention_lines.len().min(2) as u16) + 2;
                let sections = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Length(attention_height),
                        Constraint::Min(10),
                        Constraint::Length(3),
                    ])
                    .split(area);

                self.draw_compact_header(frame, sections[0]);
                self.draw_attention(
                    frame,
                    sections[1],
                    &attention_lines[..attention_lines.len().min(2)],
                );
                self.draw_compact_body(frame, sections[2]);
                self.draw_compact_footer(frame, sections[3]);
            }
        }

        if !matches!(dashboard_layout_mode(area), LayoutMode::TooSmall)
            && let Some(modal) = &self.inspect_modal
        {
            self.draw_inspect_modal(frame, area, modal);
        }
    }

    fn draw_too_small(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let text = vec![
            Line::from("BoringCache dashboard needs a larger terminal."),
            Line::from(format!(
                "Current size: {}x{}  Needed: at least 80x24",
                area.width, area.height
            )),
            Line::from("Resize the terminal or use `boringcache status` for line output."),
        ];
        let widget = Paragraph::new(text)
            .block(Block::default().title("Dashboard").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, area);
    }

    fn draw_header(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let page_count = tag_page_count(&self.tags);
        let lines = vec![
            Line::from(vec![
                Span::styled(
                    "BoringCache Dashboard",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {}", self.status.workspace.slug)),
            ]),
            Line::from(format!(
                "Period {}  Generated {}  Refreshed {} ago  Tags page {}/{}",
                self.status.period.key,
                crate::commands::status::format_relative_time(&self.status.generated_at),
                crate::commands::status::format_duration_seconds(Some(
                    self.last_refresh.elapsed().as_secs_f64()
                )),
                self.tag_page,
                page_count
            )),
        ];

        let widget =
            Paragraph::new(lines).block(Block::default().title("Workspace").borders(Borders::ALL));
        frame.render_widget(widget, area);
    }

    fn draw_compact_header(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let line = Line::from(format!(
            "{}  {}  refreshed {} ago  page {}/{}",
            self.status.workspace.slug,
            self.status.period.key,
            crate::commands::status::format_duration_seconds(Some(
                self.last_refresh.elapsed().as_secs_f64()
            )),
            self.tag_page,
            tag_page_count(&self.tags)
        ));
        let widget = Paragraph::new(vec![line])
            .block(Block::default().title("Dashboard").borders(Borders::ALL));
        frame.render_widget(widget, area);
    }

    fn draw_attention(
        &self,
        frame: &mut ratatui::Frame<'_>,
        area: Rect,
        attention_lines: &[String],
    ) {
        let lines = if attention_lines.is_empty() {
            vec![Line::from(vec![Span::styled(
                "No active alerts. Cache looks healthy for this period.",
                Style::default().fg(Color::Green),
            )])]
        } else {
            attention_lines
                .iter()
                .map(|line| {
                    Line::from(vec![
                        Span::styled("- ", Style::default().fg(Color::Yellow)),
                        Span::raw(line),
                    ])
                })
                .collect()
        };

        let widget = Paragraph::new(lines)
            .block(Block::default().title("Attention").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, area);
    }

    fn draw_body(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
            .split(area);

        self.draw_tags(frame, columns[0]);
        self.draw_summary_and_panel(frame, columns[1]);
    }

    fn draw_compact_body(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
            .split(area);

        self.draw_compact_tags(frame, columns[0]);
        self.draw_compact_summary_and_panel(frame, columns[1]);
    }

    fn draw_tags(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(7)])
            .split(area);

        let header = Row::new(vec![
            Cell::from("TYPE"),
            Cell::from("TAG"),
            Cell::from("PRIMARY"),
            Cell::from("HITS"),
            Cell::from("SIZE"),
            Cell::from("UPLOADED"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));

        let rows = self.tags.tags.iter().map(|tag| {
            Row::new(vec![
                Cell::from(tag_kind(tag)),
                Cell::from(crate::commands::status::truncate(&tag.name, 28)),
                Cell::from(crate::commands::status::truncate(&tag.primary_tag, 18)),
                Cell::from(tag.hit_count.to_string()),
                Cell::from(format_bytes(tag.stored_size_bytes)),
                Cell::from(format_optional_relative_time(tag.uploaded_at.as_deref())),
            ])
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Percentage(34),
                Constraint::Percentage(24),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    "Tags [{} | {}]",
                    if self.include_system_tags {
                        "all tags"
                    } else {
                        "human tags"
                    },
                    showing_range(&self.tags)
                ))
                .borders(Borders::ALL),
        )
        .column_spacing(1)
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

        let mut table_state = TableState::default();
        if !self.tags.tags.is_empty() {
            table_state.select(Some(self.selected_tag.min(self.tags.tags.len() - 1)));
        }
        frame.render_stateful_widget(table, sections[0], &mut table_state);

        let selected_lines = selected_tag_lines(self.selected_tag());
        let widget = Paragraph::new(selected_lines)
            .block(Block::default().title("Selected Tag").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, sections[1]);
    }

    fn draw_compact_tags(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let header = Row::new(vec![
            Cell::from("TAG"),
            Cell::from("HITS"),
            Cell::from("SIZE"),
            Cell::from("USED"),
        ])
        .style(Style::default().add_modifier(Modifier::BOLD));

        let rows = self.tags.tags.iter().map(|tag| {
            Row::new(vec![
                Cell::from(crate::commands::status::truncate(&tag.name, 20)),
                Cell::from(tag.hit_count.to_string()),
                Cell::from(format_bytes(tag.stored_size_bytes)),
                Cell::from(format_optional_relative_time(
                    tag.last_accessed_at.as_deref(),
                )),
            ])
        });

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(50),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(format!("Tags [{}]", showing_range(&self.tags)))
                .borders(Borders::ALL),
        )
        .column_spacing(1)
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

        let mut table_state = TableState::default();
        if !self.tags.tags.is_empty() {
            table_state.select(Some(self.selected_tag.min(self.tags.tags.len() - 1)));
        }
        frame.render_stateful_widget(table, area, &mut table_state);
    }

    fn draw_summary_and_panel(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(8), Constraint::Min(10)])
            .split(area);

        let summary_lines = workspace_summary_lines(&self.status);
        let summary_widget = Paragraph::new(summary_lines)
            .block(Block::default().title("Summary").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(summary_widget, sections[0]);

        let detail_sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(6)])
            .split(sections[1]);

        let tabs = Tabs::new(["Sessions", "Misses", "Tools"])
            .select(self.side_panel.index())
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().title("Details").borders(Borders::ALL));
        frame.render_widget(tabs, detail_sections[0]);

        let detail_lines = match self.side_panel {
            SidePanel::Sessions => session_lines(&self.status.sessions),
            SidePanel::Misses => miss_lines(&self.status.missed_keys),
            SidePanel::Tools => tool_lines(&self.status.tools),
        };
        let details = Paragraph::new(detail_lines)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(details, detail_sections[1]);
    }

    fn draw_compact_summary_and_panel(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(4)])
            .split(area);

        let summary_lines = compact_summary_lines(&self.status, self.selected_tag());
        let summary_widget = Paragraph::new(summary_lines)
            .block(Block::default().title("Snapshot").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(summary_widget, sections[0]);

        let detail_sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(sections[1]);

        let tabs = Tabs::new(["Sessions", "Misses", "Tools"])
            .select(self.side_panel.index())
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().title("Details").borders(Borders::ALL));
        frame.render_widget(tabs, detail_sections[0]);

        let detail_lines = match self.side_panel {
            SidePanel::Sessions => session_lines(&self.status.sessions),
            SidePanel::Misses => miss_lines(&self.status.missed_keys),
            SidePanel::Tools => tool_lines(&self.status.tools),
        };
        let details = Paragraph::new(detail_lines)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(details, detail_sections[1]);
    }

    fn draw_footer(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let status_line = self.footer_message.as_deref().map_or_else(
            || {
                format!(
                    "Auto refresh {}s  System tags {}  Panel {}",
                    self.refresh_interval.as_secs(),
                    if self.include_system_tags {
                        "on"
                    } else {
                        "off"
                    },
                    match self.side_panel {
                        SidePanel::Sessions => "sessions",
                        SidePanel::Misses => "misses",
                        SidePanel::Tools => "tools",
                    }
                )
            },
            ToString::to_string,
        );

        let lines = vec![
            Line::from(
                "Keys: arrows/jk move  Enter inspect  Tab switch panel  n/p page  s toggle system  r refresh  q quit",
            ),
            Line::from(status_line),
        ];

        let widget = Paragraph::new(lines)
            .block(Block::default().title("Help").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, area);
    }

    fn draw_compact_footer(&self, frame: &mut ratatui::Frame<'_>, area: Rect) {
        let status_line = self.footer_message.as_deref().map_or_else(
            || {
                format!(
                    "{}  system {}  {}s refresh",
                    match self.side_panel {
                        SidePanel::Sessions => "sessions",
                        SidePanel::Misses => "misses",
                        SidePanel::Tools => "tools",
                    },
                    if self.include_system_tags {
                        "on"
                    } else {
                        "off"
                    },
                    self.refresh_interval.as_secs()
                )
            },
            ToString::to_string,
        );

        let lines = vec![
            Line::from("jk/arrows move  Enter inspect  Tab panel  n/p page  s system  q quit"),
            Line::from(status_line),
        ];
        let widget = Paragraph::new(lines)
            .block(Block::default().title("Help").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, area);
    }

    fn draw_inspect_modal(&self, frame: &mut ratatui::Frame<'_>, area: Rect, modal: &InspectModal) {
        let popup = centered_rect(76, 72, area);
        frame.render_widget(Clear, popup);

        let (title, lines) = inspect_modal_lines(modal);
        let widget = Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, popup);
    }

    fn select_next_tag(&mut self) {
        if self.tags.tags.is_empty() {
            return;
        }
        self.selected_tag = (self.selected_tag + 1).min(self.tags.tags.len() - 1);
    }

    fn select_previous_tag(&mut self) {
        if self.selected_tag > 0 {
            self.selected_tag -= 1;
        }
    }

    fn selected_tag(&self) -> Option<&WorkspaceTagFeedItem> {
        self.tags.tags.get(self.selected_tag)
    }

    async fn next_page(&mut self) {
        if !self.tags.pagination.has_more {
            self.footer_message = Some("Already on the last tag page.".to_string());
            return;
        }
        self.tag_page += 1;
        self.refresh_in_place().await;
    }

    async fn previous_page(&mut self) {
        if self.tag_page == 1 {
            self.footer_message = Some("Already on the first tag page.".to_string());
            return;
        }
        self.tag_page -= 1;
        self.refresh_in_place().await;
    }

    async fn toggle_system_tags(&mut self) {
        self.include_system_tags = !self.include_system_tags;
        self.tag_page = 1;
        self.refresh_in_place().await;
    }

    async fn open_selected_tag_inspect(&mut self) {
        let Some(tag) = self.selected_tag() else {
            self.footer_message = Some("No tag selected to inspect.".to_string());
            return;
        };

        let tag_name = tag.name.clone();
        match self
            .api_client
            .inspect_cache(&self.workspace, &tag_name)
            .await
        {
            Ok(Some(data)) => {
                self.inspect_modal = Some(InspectModal::Ready {
                    tag: tag_name,
                    data: Box::new(data),
                });
            }
            Ok(None) => {
                self.inspect_modal = Some(InspectModal::Missing { tag: tag_name });
            }
            Err(err) => {
                self.inspect_modal = Some(InspectModal::Error {
                    tag: tag_name,
                    message: err.to_string(),
                });
            }
        }
    }

    async fn refresh_in_place(&mut self) {
        let selected_tag_name = self.selected_tag().map(|tag| tag.name.clone());
        match fetch_dashboard_data(
            &self.api_client,
            &self.workspace,
            &self.period,
            self.insight_limit,
            self.tag_limit,
            self.tag_page,
            self.include_system_tags,
        )
        .await
        {
            Ok((status, tags)) => {
                self.status = status;
                self.tags = tags;
                self.selected_tag = resolve_selected_tag_index(&self.tags, selected_tag_name);
                self.last_refresh = Instant::now();
                self.footer_message = None;
                self.inspect_modal = None;
            }
            Err(err) => {
                self.footer_message = Some(format!("Refresh failed: {err}"));
            }
        }
    }
}

async fn fetch_dashboard_data(
    api_client: &ApiClient,
    workspace: &str,
    period: &str,
    insight_limit: u32,
    tag_limit: u32,
    tag_page: u32,
    include_system_tags: bool,
) -> Result<(WorkspaceStatusResponse, WorkspaceTagsResponse)> {
    let offset = (tag_page.saturating_sub(1)).saturating_mul(tag_limit);
    tokio::try_join!(
        api_client.workspace_status(workspace, period, insight_limit),
        api_client.workspace_tags(workspace, None, include_system_tags, tag_limit, offset),
    )
}

fn resolve_selected_tag_index(
    tags: &WorkspaceTagsResponse,
    selected_name: Option<String>,
) -> usize {
    let Some(selected_name) = selected_name else {
        return 0;
    };

    tags.tags
        .iter()
        .position(|tag| tag.name == selected_name)
        .unwrap_or(0)
}

fn workspace_summary_lines(status: &WorkspaceStatusResponse) -> Vec<Line<'static>> {
    vec![
        Line::from(format!(
            "Inventory: {} entries  {} stored  {} versions",
            status.inventory.tagged_entries_count,
            format_bytes(status.inventory.tagged_storage_bytes),
            status.inventory.version_count
        )),
        Line::from(format!(
            "Cache: {} requests  {} hit  {} avg",
            status.operations.cache.total_requests,
            crate::commands::status::format_percent(status.operations.cache.hit_rate),
            crate::commands::status::format_millis(status.operations.cache.avg_latency_ms)
        )),
        Line::from(format!(
            "Sessions: {} healthy / {} errors  {} avg hit",
            status.operations.session_health.healthy_sessions,
            status.operations.session_health.error_sessions,
            crate::commands::status::format_percent(status.operations.session_health.avg_hit_rate)
        )),
        Line::from(format!(
            "Savings: {} served  {} written  {} dedup",
            format_bytes(status.savings.bytes_served),
            format_bytes(status.savings.bytes_written),
            format_bytes(status.savings.dedup_savings_bytes)
        )),
        Line::from(format!(
            "Misses: {} recurring  {} cold  {} degraded",
            status.operations.cache_health.recurring_misses,
            status.operations.cache_health.cold_misses,
            status.operations.cache.degraded_count + status.operations.runtime.degraded_count
        )),
    ]
}

fn compact_summary_lines(
    status: &WorkspaceStatusResponse,
    selected_tag: Option<&WorkspaceTagFeedItem>,
) -> Vec<Line<'static>> {
    let degraded_total =
        status.operations.cache.degraded_count + status.operations.runtime.degraded_count;

    let selected_line = selected_tag.map_or_else(
        || "Tag: none selected".to_string(),
        |tag| {
            format!(
                "Tag: {}  {}  {} hits",
                crate::commands::status::truncate(&tag.name, 16),
                format_bytes(tag.stored_size_bytes),
                tag.hit_count
            )
        },
    );

    vec![
        Line::from(format!(
            "Cache {} hit  {} avg",
            crate::commands::status::format_percent(status.operations.cache.hit_rate),
            crate::commands::status::format_millis(status.operations.cache.avg_latency_ms)
        )),
        Line::from(format!(
            "Inv {}  {}  {} vers",
            status.inventory.tagged_entries_count,
            format_bytes(status.inventory.tagged_storage_bytes),
            status.inventory.version_count
        )),
        Line::from(format!(
            "Sess {} ok / {} err  {} deg",
            status.operations.session_health.healthy_sessions,
            status.operations.session_health.error_sessions,
            degraded_total
        )),
        Line::from(selected_line),
    ]
}

fn selected_tag_lines(tag: Option<&WorkspaceTagFeedItem>) -> Vec<Line<'static>> {
    let Some(tag) = tag else {
        return vec![Line::from("No tags on this page.")];
    };

    vec![
        Line::from(format!("Tag: {}", tag.name)),
        Line::from(format!(
            "Type: {}  Hits: {}  Size: {}",
            tag_kind(tag),
            tag.hit_count,
            format_bytes(tag.stored_size_bytes)
        )),
        Line::from(format!(
            "Primary: {}",
            crate::commands::status::truncate(&tag.primary_tag, 52)
        )),
        Line::from(format!("Storage: {}", tag.storage_mode)),
        Line::from(format!(
            "Uploaded: {}  Last used: {}",
            format_optional_relative_time(tag.uploaded_at.as_deref()),
            format_optional_relative_time(tag.last_accessed_at.as_deref())
        )),
    ]
}

fn session_lines(sessions: &[WorkspaceStatusSession]) -> Vec<Line<'static>> {
    if sessions.is_empty() {
        return vec![Line::from("No recent sessions for this period.")];
    }

    let mut lines = Vec::new();
    for session in sessions {
        lines.push(Line::from(format!(
            "{}  {} hit  {}  {}",
            session.tool,
            crate::commands::status::format_percent(session.hit_rate),
            crate::commands::status::format_duration_seconds(session.duration_seconds),
            crate::commands::status::format_relative_time(&session.created_at)
        )));
        lines.push(Line::from(format!(
            "  {} hits  {} misses  {} errors  {} read",
            session.hit_count,
            session.miss_count,
            session.error_count,
            format_bytes(session.bytes_read)
        )));
    }
    lines
}

fn miss_lines(misses: &[WorkspaceStatusMissedKey]) -> Vec<Line<'static>> {
    if misses.is_empty() {
        return vec![Line::from("No hot misses for this period.")];
    }

    let mut lines = Vec::new();
    for miss in misses {
        let prefix = miss
            .sampled_key_prefix
            .as_deref()
            .map(|value| crate::commands::status::truncate(value, 42))
            .unwrap_or_else(|| crate::commands::status::truncate(&miss.key_hash, 18));
        lines.push(Line::from(format!(
            "{}  {} misses  {}",
            miss.tool, miss.miss_count, miss.miss_state
        )));
        lines.push(Line::from(format!(
            "  {}  seen {}",
            prefix,
            miss.last_seen_at
                .as_deref()
                .map(crate::commands::status::format_relative_time)
                .unwrap_or_else(|| "unknown".to_string())
        )));
    }
    lines
}

fn tool_lines(tools: &[WorkspaceStatusTool]) -> Vec<Line<'static>> {
    if tools.is_empty() {
        return vec![Line::from("No tool activity for this period.")];
    }

    tools
        .iter()
        .map(|tool| {
            Line::from(format!(
                "{}  {} lookups  {} hit  {} served",
                tool.tool,
                tool.lookup_total,
                crate::commands::status::format_percent(tool.hit_rate),
                format_bytes(tool.bytes_total)
            ))
        })
        .collect()
}

fn attention_items(status: &WorkspaceStatusResponse) -> Vec<String> {
    let mut items = Vec::new();

    let degraded_total =
        status.operations.cache.degraded_count + status.operations.runtime.degraded_count;
    if degraded_total > 0 {
        items.push(format!(
            "{} degraded operations detected (cache {} / runtime {}).",
            degraded_total,
            status.operations.cache.degraded_count,
            status.operations.runtime.degraded_count
        ));
    }

    if status.operations.session_health.error_sessions > 0 {
        items.push(format!(
            "{} recent sessions had errors.",
            status.operations.session_health.error_sessions
        ));
    }

    if status.operations.cache.hit_rate < 60.0 {
        items.push(format!(
            "Cache hit rate is low at {}.",
            crate::commands::status::format_percent(status.operations.cache.hit_rate)
        ));
    }

    if status.operations.cache_health.warm_hit_rate < 70.0 {
        items.push(format!(
            "Warm hit rate is only {}.",
            crate::commands::status::format_percent(status.operations.cache_health.warm_hit_rate)
        ));
    }

    if status.operations.cache_health.recurring_misses > 0 {
        items.push(format!(
            "{} recurring misses are repeating across sessions.",
            status.operations.cache_health.recurring_misses
        ));
    }

    if status.inventory.orphaned_entries_count > 0 && status.inventory.orphaned_storage_bytes > 0 {
        items.push(format!(
            "{} orphaned entries are using {}.",
            status.inventory.orphaned_entries_count,
            format_bytes(status.inventory.orphaned_storage_bytes)
        ));
    }

    items
}

fn inspect_modal_lines(modal: &InspectModal) -> (String, Vec<Line<'static>>) {
    match modal {
        InspectModal::Missing { tag } => (
            format!("Inspect {}", tag),
            vec![
                Line::from("The selected tag could not be resolved anymore."),
                Line::from("Refresh the dashboard and try again."),
                Line::from("Press Esc to close."),
            ],
        ),
        InspectModal::Error { tag, message } => (
            format!("Inspect {}", tag),
            vec![
                Line::from("Failed to load cache details."),
                Line::from(crate::commands::status::truncate(message, 100)),
                Line::from("Press Esc to close."),
            ],
        ),
        InspectModal::Ready { tag, data } => {
            let entry = &data.entry;
            let mut lines = vec![
                Line::from(format!(
                    "Workspace: {}  Matched by: {}",
                    data.workspace.slug, data.identifier.matched_by
                )),
                Line::from(format!(
                    "Entry: {}",
                    crate::commands::status::truncate(&entry.id, 72)
                )),
                Line::from(format!(
                    "Status: {}  Storage: {}  Hits: {}",
                    entry.status, entry.storage_mode, entry.hit_count
                )),
                Line::from(format!(
                    "Primary tag: {}",
                    entry.primary_tag.as_deref().unwrap_or("-")
                )),
                Line::from(format!(
                    "Size: {} stored  {} uncompressed  {} compressed",
                    format_bytes(entry.stored_size_bytes),
                    format_optional_bytes(entry.uncompressed_size),
                    format_optional_bytes(entry.compressed_size)
                )),
                Line::from(format!(
                    "Files: {}  Blobs: {}  Blob bytes: {}",
                    format_optional_u32(entry.file_count),
                    format_optional_u64(entry.blob_count),
                    format_optional_bytes(entry.blob_total_size_bytes)
                )),
                Line::from(format!(
                    "Uploaded: {}  Last used: {}  Expires: {}",
                    format_optional_relative_time(entry.uploaded_at.as_deref()),
                    format_optional_relative_time(entry.last_accessed_at.as_deref()),
                    format_optional_relative_time(entry.expires_at.as_deref())
                )),
                Line::from(format!(
                    "Encrypted: {}  Signed: {}  Verified: {}",
                    yes_no(entry.encrypted),
                    yes_no(entry.server_signed),
                    yes_no(entry.storage_verified)
                )),
                Line::from(format!(
                    "Manifest root: {}",
                    crate::commands::status::truncate(&entry.manifest_root_digest, 76)
                )),
            ];

            if let Some(versions) = &data.versions {
                lines.push(Line::from(format!(
                    "Versions: {} of {} retained  {} total storage",
                    versions.version_count,
                    versions.max_versions,
                    format_bytes(versions.total_storage_bytes)
                )));
            }

            if let Some(perf) = &data.performance {
                lines.push(Line::from(format!(
                    "Performance: {} restores  {} saves  {} errors  avg restore {}",
                    perf.restores,
                    perf.saves,
                    perf.errors,
                    crate::commands::status::format_millis(perf.avg_restore_ms)
                )));
            }

            if !data.tags.is_empty() {
                let joined = data
                    .tags
                    .iter()
                    .map(|tag| tag.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(Line::from(format!(
                    "Tags: {}",
                    crate::commands::status::truncate(&joined, 86)
                )));
            }

            lines.push(Line::from("Press Esc to close."));
            (format!("Inspect {}", tag), lines)
        }
    }
}

fn format_optional_relative_time(value: Option<&str>) -> String {
    value
        .map(crate::commands::status::format_relative_time)
        .unwrap_or_else(|| "-".to_string())
}

fn format_optional_bytes(value: Option<u64>) -> String {
    value.map(format_bytes).unwrap_or_else(|| "-".to_string())
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn format_optional_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn tag_kind(tag: &WorkspaceTagFeedItem) -> &'static str {
    if tag.system {
        "system"
    } else if tag.primary {
        "primary"
    } else {
        "alias"
    }
}

fn showing_range(response: &WorkspaceTagsResponse) -> String {
    let pagination = &response.pagination;
    if pagination.total == 0 || pagination.returned == 0 {
        return format!("0 of {}", pagination.total);
    }

    format!(
        "{}-{} of {}",
        pagination.offset + 1,
        pagination.offset + pagination.returned,
        pagination.total
    )
}

fn tag_page_count(response: &WorkspaceTagsResponse) -> u32 {
    let pagination = &response.pagination;
    if pagination.total == 0 || pagination.limit == 0 {
        1
    } else {
        pagination.total.div_ceil(pagination.limit)
    }
}

fn dashboard_layout_mode(area: Rect) -> LayoutMode {
    if area.width < 80 || area.height < 24 {
        LayoutMode::TooSmall
    } else if area.width < 100 || area.height < 28 {
        LayoutMode::Compact
    } else {
        LayoutMode::Full
    }
}

fn centered_rect(width_pct: u16, height_pct: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height_pct) / 2),
            Constraint::Percentage(height_pct),
            Constraint::Percentage((100 - height_pct) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_pct) / 2),
            Constraint::Percentage(width_pct),
            Constraint::Percentage((100 - width_pct) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
#[path = "dashboard_tests.rs"]
mod tests;

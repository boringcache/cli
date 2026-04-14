use anyhow::Result;
use crossbeam_channel::{Receiver, RecvTimeoutError};
use humansize::{DECIMAL, format_size};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{Event, Summary};

struct SessionState {
    title: String,
    total_steps: u8,
    current_step: u8,
    current_name: String,
    current_detail: Option<String>,
    line_open: bool,
    last_line_len: usize,
    prefix: Option<String>,
}

pub(super) struct Renderer {
    event_rx: Receiver<Event>,
    sessions: HashMap<String, SessionState>,
    should_stop: Arc<AtomicBool>,
    is_ci: bool,
    inline_override: Option<bool>,
}

impl Renderer {
    pub(super) fn new(event_rx: Receiver<Event>) -> Self {
        let is_ci = detect_progress_mode();
        Self {
            event_rx,
            sessions: HashMap::new(),
            should_stop: Arc::new(AtomicBool::new(false)),
            is_ci,
            inline_override: None,
        }
    }

    pub(super) fn run(mut self) -> Result<()> {
        while !self.should_stop.load(Ordering::Relaxed) {
            match self.event_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => self.handle_event(event)?,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        self.flush_all_lines()?;
        Ok(())
    }

    fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::SessionStart {
                id,
                title,
                total_steps,
            } => self.handle_session_start(id, title, total_steps)?,
            Event::StepStart {
                id,
                step,
                name,
                detail,
            } => self.handle_step_start(id, step, name, detail)?,
            Event::StepProgress {
                id,
                step,
                progress: _,
                detail,
            } => self.handle_step_progress(id, step, detail)?,
            Event::StepComplete { id, step, duration } => {
                self.handle_step_complete(id, step, duration)?
            }
            Event::SessionComplete {
                id,
                duration,
                summary,
            } => self.handle_session_complete(id, duration, summary)?,
            Event::SessionError { id, error } => self.handle_session_error(id, error)?,
            Event::Info { message } => {
                self.flush_all_lines()?;
                println!("info: {}", message);
            }
            Event::Warning { message } => {
                self.flush_all_lines()?;
                eprintln!("warning: {}", message);
            }
            Event::Error { message } => {
                self.flush_all_lines()?;
                eprintln!("error: {}", message);
            }
            Event::SubstepStart {
                id: _,
                parent_step: _,
                index,
                total,
                name,
                detail,
            } => {
                self.flush_all_lines()?;
                let line = if let Some(detail) = detail {
                    format!("    [{}/{}] {} {}", index, total, name, detail)
                } else {
                    format!("    [{}/{}] {}", index, total, name)
                };
                println!("{}", line);
            }
            Event::SubstepProgress {
                id: _,
                parent_step: _,
                index: _,
                total: _,
                progress: _,
                detail: _,
            } => {}
            Event::SubstepComplete {
                id: _,
                parent_step: _,
                index,
                total,
                duration,
                detail,
            } => {
                self.flush_all_lines()?;
                let dur_str = format!("done in {:.0}ms", duration.as_millis());
                let line = if let Some(detail) = detail {
                    format!("    [{}/{}] {} {}", index, total, dur_str, detail)
                } else {
                    format!("    [{}/{}] {}", index, total, dur_str)
                };
                println!("{}", line);
            }
            Event::SetInlineEnabled { enabled } => {
                self.inline_override = Some(enabled);
            }
        }
        Ok(())
    }

    fn handle_session_start(&mut self, id: String, title: String, total_steps: u8) -> Result<()> {
        self.flush_all_lines()?;

        use std::io::Write;
        io::stdout().flush()?;

        println!("⇒ {}", title);
        let prefix = Self::extract_prefix(&title);
        let state = SessionState {
            title,
            total_steps,
            current_step: 0,
            current_name: String::new(),
            current_detail: None,
            line_open: false,
            last_line_len: 0,
            prefix,
        };
        self.sessions.insert(id, state);
        Ok(())
    }

    fn handle_step_start(
        &mut self,
        id: String,
        step: u8,
        name: String,
        detail: Option<String>,
    ) -> Result<()> {
        let inline = self.inline_enabled();
        if let Some(session) = self.sessions.get_mut(&id) {
            Self::finalize_line(session)?;
            session.current_step = step;
            session.current_name = name;
            session.current_detail = detail;
            if inline {
                let line = Self::format_step_line(
                    session.current_step,
                    session.total_steps,
                    &session.current_name,
                    session.current_detail.as_deref(),
                );
                Self::render_inline(session, &line)?;
                return Ok(());
            }

            if self.inline_override == Some(false) {
                return Ok(());
            }

            let mut line = Self::format_step_line(
                session.current_step,
                session.total_steps,
                &session.current_name,
                session.current_detail.as_deref(),
            );
            if let Some(prefix) = session.prefix.as_deref() {
                line = format!("{prefix} {line}");
            }
            println!(" {}", line);
        }
        Ok(())
    }

    fn handle_step_progress(&mut self, id: String, step: u8, detail: Option<String>) -> Result<()> {
        let inline = self.inline_enabled();
        if let Some(session) = self.sessions.get_mut(&id) {
            session.current_step = step;
            if let Some(detail) = detail {
                session.current_detail = Some(detail);
            }
            let line = Self::format_step_line(
                session.current_step,
                session.total_steps,
                &session.current_name,
                session.current_detail.as_deref(),
            );
            if inline {
                Self::render_inline(session, &line)?;
            }
        }
        Ok(())
    }

    fn handle_step_complete(&mut self, id: String, step: u8, duration: Duration) -> Result<()> {
        let inline = self.inline_enabled();
        if let Some(session) = self.sessions.get_mut(&id) {
            session.current_step = step;
            let done_detail = format!("(done in {})", format_duration(duration));
            session.current_detail = Some(done_detail);
            let mut line = Self::format_step_line(
                session.current_step,
                session.total_steps,
                &session.current_name,
                session.current_detail.as_deref(),
            );
            if inline {
                Self::render_inline(session, &line)?;
                Self::finalize_line(session)?;
            } else {
                if let Some(prefix) = session.prefix.as_deref() {
                    line = format!("{prefix} {line}");
                }
                println!(" {}", line);
            }
        }
        Ok(())
    }

    fn handle_session_complete(
        &mut self,
        id: String,
        duration: Duration,
        summary: Summary,
    ) -> Result<()> {
        if let Some(mut session) = self.sessions.remove(&id) {
            Self::finalize_line(&mut session)?;

            println!();
            let size_str = format_size(summary.size_bytes, DECIMAL);
            let files_str = if summary.file_count == 1 {
                "1 file".to_string()
            } else {
                format!("{} files", format_number(summary.file_count as u64))
            };

            println!(
                "Completed {} ({}, {}, {})",
                session.title,
                format_duration(duration),
                size_str,
                files_str
            );

            if let Some(digest) = summary.digest {
                println!("    Digest: {}", digest);
            }

            if let Some(path) = summary.path {
                println!("    Path: {}", path);
            }
        }
        Ok(())
    }

    fn handle_session_error(&mut self, id: String, error: String) -> Result<()> {
        if let Some(mut session) = self.sessions.remove(&id) {
            Self::finalize_line(&mut session)?;
            eprintln!("error: {} - {}", session.title, error);
        }
        Ok(())
    }

    fn flush_all_lines(&mut self) -> Result<()> {
        for session in self.sessions.values_mut() {
            Self::finalize_line(session)?;
        }
        Ok(())
    }

    fn inline_enabled(&self) -> bool {
        if let Some(enabled) = self.inline_override {
            return enabled;
        }
        !self.is_ci && self.sessions.len() <= 1
    }

    fn render_inline(session: &mut SessionState, line: &str) -> Result<()> {
        let display = format!(" {}", line);
        let mut stdout = io::stdout();
        if session.line_open {
            write!(stdout, "\r{}", display)?;
            if session.last_line_len > display.len() {
                write!(
                    stdout,
                    "{}",
                    " ".repeat(session.last_line_len - display.len())
                )?;
                write!(stdout, "\r{}", display)?;
            }
        } else {
            write!(stdout, "{}", display)?;
        }
        stdout.flush()?;
        session.line_open = true;
        session.last_line_len = display.len();
        Ok(())
    }

    fn finalize_line(session: &mut SessionState) -> Result<()> {
        if session.line_open {
            let mut stdout = io::stdout();
            writeln!(stdout)?;
            stdout.flush()?;
            session.line_open = false;
            session.last_line_len = 0;
        }
        Ok(())
    }

    fn format_step_line(step: u8, total: u8, name: &str, detail: Option<&str>) -> String {
        match detail {
            Some(detail) if !detail.is_empty() => {
                format!("[{}/{}] {} {}", step, total, name, detail)
            }
            _ => format!("[{}/{}] {}", step, total, name),
        }
    }

    fn extract_prefix(title: &str) -> Option<String> {
        if let Some(start) = title.find('[')
            && let Some(end) = title[start + 1..].find(']')
        {
            let inner = title[start + 1..start + 1 + end].trim();
            if !inner.is_empty() {
                return Some(inner.to_string());
            }
        }

        if let Some(rest) = title.strip_prefix("Saving ") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if let Some(rest) = title.strip_prefix("Restoring cache ") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if let Some(rest) = title.strip_prefix("Deleting cache ") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        None
    }
}

fn detect_progress_mode() -> bool {
    use std::io::IsTerminal;

    !std::io::stdout().is_terminal() || std::env::var("CI").is_ok()
}

pub(super) fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

pub(super) fn format_duration(duration: Duration) -> String {
    if duration.as_millis() >= 1_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

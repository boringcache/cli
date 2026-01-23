pub mod common;

pub use common::{ProgressFormat, ProgressSession, StepHandle, TransferProgress};

use anyhow::{self, Result};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use humansize::{format_size, DECIMAL};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Event {
    SessionStart {
        id: String,
        title: String,
        total_steps: u8,
    },
    StepStart {
        id: String,
        step: u8,
        name: String,
        detail: Option<String>,
    },
    StepProgress {
        id: String,
        step: u8,
        progress: f64,
        detail: Option<String>,
    },
    StepComplete {
        id: String,
        step: u8,
        duration: Duration,
    },
    SessionComplete {
        id: String,
        duration: Duration,
        summary: Summary,
    },
    SessionError {
        id: String,
        error: String,
    },
    Info {
        message: String,
    },
    Warning {
        message: String,
    },
    Error {
        message: String,
    },
    SubstepStart {
        id: String,
        parent_step: u8,
        index: u32,
        total: u32,
        name: String,
        detail: Option<String>,
    },
    SubstepProgress {
        id: String,
        parent_step: u8,
        index: u32,
        total: u32,
        progress: f64,
        detail: Option<String>,
    },
    SubstepComplete {
        id: String,
        parent_step: u8,
        index: u32,
        total: u32,
        duration: Duration,
        detail: Option<String>,
    },
    SetInlineEnabled {
        enabled: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub size_bytes: u64,
    pub file_count: u32,
    pub digest: Option<String>,
    pub path: Option<String>,
}

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

pub struct Renderer {
    event_rx: Receiver<Event>,
    sessions: HashMap<String, SessionState>,
    should_stop: Arc<AtomicBool>,
    is_ci: bool,
    inline_override: Option<bool>,
}

impl Renderer {
    fn new(event_rx: Receiver<Event>) -> Self {
        let is_ci = detect_progress_mode();
        Self {
            event_rx,
            sessions: HashMap::new(),
            should_stop: Arc::new(AtomicBool::new(false)),
            is_ci,
            inline_override: None,
        }
    }

    fn run(mut self) -> Result<()> {
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
        if let Some(start) = title.find('[') {
            if let Some(end) = title[start + 1..].find(']') {
                let inner = title[start + 1..start + 1 + end].trim();
                if !inner.is_empty() {
                    return Some(inner.to_string());
                }
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

#[derive(Clone)]
pub struct Reporter {
    tx: Sender<Event>,
}

impl Reporter {
    pub fn new_noop() -> Self {
        let (tx, _rx) = crossbeam_channel::unbounded();
        Self { tx }
    }

    pub fn send(&self, event: Event) -> Result<()> {
        self.tx.send(event)?;
        Ok(())
    }

    pub fn session_start(&self, id: String, title: String, total_steps: u8) -> Result<()> {
        self.send(Event::SessionStart {
            id,
            title,
            total_steps,
        })
    }

    pub fn step_start(
        &self,
        id: String,
        step: u8,
        name: String,
        detail: Option<String>,
    ) -> Result<()> {
        self.send(Event::StepStart {
            id,
            step,
            name,
            detail,
        })
    }

    pub fn step_progress(
        &self,
        id: String,
        step: u8,
        progress: f64,
        detail: Option<String>,
    ) -> Result<()> {
        self.send(Event::StepProgress {
            id,
            step,
            progress,
            detail,
        })
    }

    pub fn step_complete(&self, id: String, step: u8, duration: Duration) -> Result<()> {
        self.send(Event::StepComplete { id, step, duration })
    }

    pub fn session_complete(&self, id: String, duration: Duration, summary: Summary) -> Result<()> {
        self.send(Event::SessionComplete {
            id,
            duration,
            summary,
        })
    }

    pub fn session_error(&self, id: String, error: String) -> Result<()> {
        self.send(Event::SessionError { id, error })
    }

    pub fn info(&self, message: String) -> Result<()> {
        self.send(Event::Info { message })
    }

    pub fn warning(&self, message: String) -> Result<()> {
        self.send(Event::Warning { message })
    }

    pub fn error(&self, message: String) -> Result<()> {
        self.send(Event::Error { message })
    }

    pub fn substep_start(
        &self,
        id: String,
        parent_step: u8,
        index: u32,
        total: u32,
        name: String,
        detail: Option<String>,
    ) -> Result<()> {
        self.send(Event::SubstepStart {
            id,
            parent_step,
            index,
            total,
            name,
            detail,
        })
    }

    pub fn substep_progress(
        &self,
        id: String,
        parent_step: u8,
        index: u32,
        total: u32,
        progress: f64,
        detail: Option<String>,
    ) -> Result<()> {
        self.send(Event::SubstepProgress {
            id,
            parent_step,
            index,
            total,
            progress,
            detail,
        })
    }

    pub fn substep_complete(
        &self,
        id: String,
        parent_step: u8,
        index: u32,
        total: u32,
        duration: Duration,
        detail: Option<String>,
    ) -> Result<()> {
        self.send(Event::SubstepComplete {
            id,
            parent_step,
            index,
            total,
            duration,
            detail,
        })
    }

    pub fn set_inline_enabled(&self, enabled: bool) -> Result<()> {
        self.send(Event::SetInlineEnabled { enabled })
    }
}

pub struct System {
    reporter: Option<Reporter>,
    renderer_handle: Option<thread::JoinHandle<Result<()>>>,
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl System {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let renderer = Renderer::new(rx);

        let renderer_handle = thread::spawn(move || renderer.run());
        let reporter = Reporter { tx };

        Self {
            reporter: Some(reporter),
            renderer_handle: Some(renderer_handle),
        }
    }

    pub fn reporter(&self) -> Reporter {
        self.reporter
            .as_ref()
            .expect("progress reporter accessed after shutdown - this is a programming error")
            .clone()
    }

    pub fn try_reporter(&self) -> Option<Reporter> {
        self.reporter.as_ref().cloned()
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.close_channel();
        self.join_renderer()?;
        Ok(())
    }

    fn close_channel(&mut self) {
        if let Some(reporter) = self.reporter.take() {
            drop(reporter);
        }
    }

    fn join_renderer(&mut self) -> Result<()> {
        if let Some(handle) = self.renderer_handle.take() {
            match handle.join() {
                Ok(res) => res?,
                Err(panic) => {
                    return Err(anyhow::anyhow!(
                        "Progress renderer thread panicked: {:?}",
                        panic
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Drop for System {
    fn drop(&mut self) {
        self.close_channel();
        let _ = self.join_renderer();
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_millis() >= 1_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

pub fn format_bytes(bytes: u64) -> String {
    format_size(bytes, DECIMAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(500), "500");
        assert_eq!(format_number(1500), "1.5K");
        assert_eq!(format_number(1500000), "1.5M");
    }

    #[tokio::test]
    async fn test_progress_system() {
        let system = System::new();
        let reporter = system.reporter();

        reporter
            .session_start("test".to_string(), "Test Operation".to_string(), 2)
            .unwrap();
        reporter
            .step_start("test".to_string(), 1, "Step 1".to_string(), None)
            .unwrap();
        reporter
            .step_complete("test".to_string(), 1, Duration::from_millis(100))
            .unwrap();

        let summary = Summary {
            size_bytes: 1024,
            file_count: 5,
            digest: Some("abcd1234".to_string()),
            path: Some("/tmp/test".to_string()),
        };

        reporter
            .session_complete("test".to_string(), Duration::from_secs(1), summary)
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        drop(reporter);
        system.shutdown().unwrap();
    }
}

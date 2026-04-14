pub mod common;
mod model;
mod render;

pub use common::{ProgressFormat, ProgressSession, StepHandle, TransferProgress};
pub use model::{Event, Summary};

use anyhow::{self, Result};
use crossbeam_channel::Sender;
use humansize::{DECIMAL, format_size};
use std::thread;
use std::time::Duration;

use render::Renderer;
#[cfg(test)]
use render::format_number;

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

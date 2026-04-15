use anyhow::Result;
use crossbeam_channel::Sender;
use std::time::Duration;

use super::{Event, Summary};

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

    pub(super) fn from_sender(tx: Sender<Event>) -> Self {
        Self { tx }
    }
}

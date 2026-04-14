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

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub struct ExitCodeError {
    code: i32,
    message: Option<String>,
}

impl ExitCodeError {
    pub fn silent(code: i32) -> Self {
        Self {
            code,
            message: None,
        }
    }

    pub fn with_message(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }

    pub fn code(&self) -> i32 {
        self.code
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl Display for ExitCodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(message) = self.message() {
            write!(f, "{message}")
        } else {
            write!(f, "process exited with code {}", self.code)
        }
    }
}

impl Error for ExitCodeError {}

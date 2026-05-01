use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
enum RegistryErrorBody {
    PlainText,
    Json { code: String },
}

#[derive(Debug)]
pub struct RegistryError {
    pub(crate) status: StatusCode,
    pub(crate) retry_after: Option<std::time::Duration>,
    message: String,
    body: RegistryErrorBody,
}

impl RegistryError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            retry_after: None,
            message: message.into(),
            body: RegistryErrorBody::PlainText,
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn with_json_code(mut self, code: impl Into<String>) -> Self {
        self.body = RegistryErrorBody::Json { code: code.into() };
        self
    }

    pub(crate) fn with_retry_after(mut self, retry_after: Option<std::time::Duration>) -> Self {
        self.retry_after = retry_after;
        self
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        match self.body {
            RegistryErrorBody::PlainText => (
                self.status,
                [("Content-Type", "text/plain; charset=utf-8")],
                self.message,
            )
                .into_response(),
            RegistryErrorBody::Json { code } => (
                self.status,
                [("Content-Type", "application/json")],
                serde_json::json!({
                    "code": code,
                    "message": self.message,
                    "error": {
                        "code": code,
                        "message": self.message,
                    }
                })
                .to_string(),
            )
                .into_response(),
        }
    }
}

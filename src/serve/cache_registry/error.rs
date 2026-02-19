use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub struct RegistryError {
    pub(crate) status: StatusCode,
    message: String,
}

impl RegistryError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
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
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        (
            self.status,
            [("Content-Type", "text/plain; charset=utf-8")],
            self.message,
        )
            .into_response()
    }
}

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct OciErrorEntry {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct OciErrorBody {
    errors: Vec<OciErrorEntry>,
}

#[derive(Debug)]
pub struct OciError {
    status: StatusCode,
    body: OciErrorBody,
}

impl OciError {
    fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: OciErrorBody {
                errors: vec![OciErrorEntry {
                    code: code.to_string(),
                    message: message.into(),
                    detail: None,
                }],
            },
        }
    }

    pub fn manifest_unknown(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", detail)
    }

    pub fn blob_unknown(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", detail)
    }

    pub fn digest_invalid(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "DIGEST_INVALID", detail)
    }

    pub fn blob_upload_unknown(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "BLOB_UPLOAD_UNKNOWN", detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", detail)
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "UNSUPPORTED", detail)
    }

    pub fn name_unknown(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NAME_UNKNOWN", detail)
    }

    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn message(&self) -> &str {
        self.body
            .errors
            .first()
            .map(|e| e.message.as_str())
            .unwrap_or("unknown")
    }
}

impl IntoResponse for OciError {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&self.body).unwrap_or_default();
        (self.status, [("Content-Type", "application/json")], body).into_response()
    }
}

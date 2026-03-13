use std::fmt;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConflictMetadata {
    pub current_version: Option<String>,
    pub current_cache_entry_id: Option<String>,
    pub current_tag: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingMetadata {
    pub code: Option<String>,
    pub upload_session_id: Option<String>,
    pub publish_attempt_id: Option<String>,
    pub poll_path: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Debug)]
pub enum BoringCacheError {
    ConfigNotFound,
    TokenNotFound,
    ApiError(String),
    IoError(String),
    NetworkError(String),
    ConnectionError(String),
    RequestConfiguration(String),
    CacheMiss,
    CachePending {
        metadata: Option<PendingMetadata>,
    },
    CacheConflict {
        message: String,
        metadata: Option<ConflictMetadata>,
    },
    WorkspaceNotFound(String),
    AuthenticationFailed(String),
}

impl BoringCacheError {
    pub fn cache_conflict(message: impl Into<String>) -> Self {
        Self::CacheConflict {
            message: message.into(),
            metadata: None,
        }
    }

    pub fn cache_conflict_with_metadata(
        message: impl Into<String>,
        metadata: ConflictMetadata,
    ) -> Self {
        Self::CacheConflict {
            message: message.into(),
            metadata: Some(metadata),
        }
    }

    pub fn cache_pending() -> Self {
        Self::CachePending { metadata: None }
    }

    pub fn cache_pending_with_metadata(metadata: PendingMetadata) -> Self {
        Self::CachePending {
            metadata: Some(metadata),
        }
    }

    pub fn conflict_message(&self) -> Option<&str> {
        match self {
            Self::CacheConflict { message, .. } => Some(message),
            _ => None,
        }
    }

    pub fn conflict_metadata(&self) -> Option<&ConflictMetadata> {
        match self {
            Self::CacheConflict { metadata, .. } => metadata.as_ref(),
            _ => None,
        }
    }

    pub fn pending_metadata(&self) -> Option<&PendingMetadata> {
        match self {
            Self::CachePending { metadata } => metadata.as_ref(),
            _ => None,
        }
    }
}

impl fmt::Display for BoringCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoringCacheError::ConfigNotFound => write!(
                f,
                "Config file not found. Please run 'boringcache auth --token <token>' first"
            ),
            BoringCacheError::TokenNotFound => write!(
                f,
                "API token not found. Please run 'boringcache auth --token <token>' first"
            ),
            BoringCacheError::ApiError(msg) => write!(f, "API Error: {msg}"),
            BoringCacheError::IoError(msg) => write!(f, "IO Error: {msg}"),
            BoringCacheError::NetworkError(msg) => write!(f, "Network Error: {msg}"),
            BoringCacheError::ConnectionError(msg) => write!(f, "{msg}"),
            BoringCacheError::RequestConfiguration(msg) => write!(f, "{msg}"),
            BoringCacheError::CacheMiss => write!(f, "Cache miss"),
            BoringCacheError::CachePending { .. } => write!(f, "Cache upload in progress"),
            BoringCacheError::CacheConflict { message, .. } => write!(f, "{message}"),
            BoringCacheError::WorkspaceNotFound(workspace) => {
                write!(f, "Workspace '{workspace}' not found")
            }
            BoringCacheError::AuthenticationFailed(msg) => {
                write!(f, "Authentication failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for BoringCacheError {}

pub fn is_connection_error(err: &anyhow::Error) -> bool {
    if let Some(bc_error) = err.downcast_ref::<BoringCacheError>() {
        return matches!(bc_error, BoringCacheError::ConnectionError(_));
    }

    let err_str = err.to_string().to_lowercase();
    err_str.contains("cannot connect")
        || err_str.contains("connection refused")
        || err_str.contains("timed out")
        || err_str.contains("timeout")
        || err_str.contains("authentication failed")
}

pub fn is_non_retryable_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<BoringCacheError>()
        .is_some_and(|bc_error| matches!(bc_error, BoringCacheError::RequestConfiguration(_)))
}

impl From<std::io::Error> for BoringCacheError {
    fn from(err: std::io::Error) -> Self {
        BoringCacheError::IoError(err.to_string())
    }
}

impl From<reqwest::Error> for BoringCacheError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_connect() {
            BoringCacheError::ConnectionError(
                "ERROR: Cannot connect to BoringCache server. Please check:\n\
                 • Is the API URL correct? (Check with: boringcache config)\n\
                 • Is there a firewall blocking the connection?"
                    .to_string(),
            )
        } else if err.is_timeout() {
            BoringCacheError::ConnectionError(
                "TIMEOUT: Connection timed out. The server might be overloaded or unreachable."
                    .to_string(),
            )
        } else if err.is_builder() {
            BoringCacheError::RequestConfiguration(format!(
                "Invalid API request before send: {err}. Check BORINGCACHE_API_URL and auth token formatting, especially leading or trailing whitespace."
            ))
        } else if err.is_request() {
            BoringCacheError::NetworkError(format!("Request failed: {err}"))
        } else {
            BoringCacheError::NetworkError(err.to_string())
        }
    }
}

impl From<serde_json::Error> for BoringCacheError {
    fn from(err: serde_json::Error) -> Self {
        BoringCacheError::ApiError(format!("JSON parsing error: {err}"))
    }
}

impl From<anyhow::Error> for BoringCacheError {
    fn from(err: anyhow::Error) -> Self {
        BoringCacheError::ApiError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        assert!(BoringCacheError::ConfigNotFound
            .to_string()
            .contains("Config file not found"));
        assert!(BoringCacheError::TokenNotFound
            .to_string()
            .contains("API token not found"));
        assert!(BoringCacheError::CacheMiss.to_string().contains("miss"));
        assert!(BoringCacheError::cache_pending()
            .to_string()
            .contains("in progress"));
    }

    #[test]
    fn test_error_with_context() {
        let api_err = BoringCacheError::ApiError("test error".to_string());
        assert!(api_err.to_string().contains("test error"));

        let ws_err = BoringCacheError::WorkspaceNotFound("my-workspace".to_string());
        assert!(ws_err.to_string().contains("my-workspace"));

        let conflict_err = BoringCacheError::cache_conflict("tag already claimed");
        assert!(conflict_err.to_string().contains("tag already claimed"));

        let auth_err = BoringCacheError::AuthenticationFailed("invalid token".to_string());
        assert!(auth_err.to_string().contains("invalid token"));

        let request_config_err =
            BoringCacheError::RequestConfiguration("invalid request".to_string());
        assert!(request_config_err.to_string().contains("invalid request"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let boring_err: BoringCacheError = io_err.into();
        assert!(matches!(boring_err, BoringCacheError::IoError(_)));
    }

    #[test]
    fn test_json_error_conversion() {
        let json_err = serde_json::from_str::<String>("invalid json").unwrap_err();
        let boring_err: BoringCacheError = json_err.into();
        assert!(matches!(boring_err, BoringCacheError::ApiError(_)));
    }

    #[test]
    fn test_non_retryable_error_detection() {
        let err: anyhow::Error =
            BoringCacheError::RequestConfiguration("bad header".to_string()).into();
        assert!(is_non_retryable_error(&err));
        assert!(!is_connection_error(&err));
    }
}

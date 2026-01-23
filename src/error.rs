use std::fmt;

#[derive(Debug)]
pub enum BoringCacheError {
    ConfigNotFound,
    TokenNotFound,
    ApiError(String),
    IoError(String),
    NetworkError(String),
    ConnectionError(String),
    CacheMiss,
    CachePending,
    CacheConflict(String),
    WorkspaceNotFound(String),
    AuthenticationFailed(String),
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
            BoringCacheError::CacheMiss => write!(f, "Cache miss"),
            BoringCacheError::CachePending => write!(f, "Cache upload in progress"),
            BoringCacheError::CacheConflict(msg) => write!(f, "{msg}"),
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
    let err_str = err.to_string().to_lowercase();
    err_str.contains("cannot connect")
        || err_str.contains("connection refused")
        || err_str.contains("timed out")
        || err_str.contains("timeout")
        || err_str.contains("authentication failed")
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
        assert!(BoringCacheError::CachePending
            .to_string()
            .contains("in progress"));
    }

    #[test]
    fn test_error_with_context() {
        let api_err = BoringCacheError::ApiError("test error".to_string());
        assert!(api_err.to_string().contains("test error"));

        let ws_err = BoringCacheError::WorkspaceNotFound("my-workspace".to_string());
        assert!(ws_err.to_string().contains("my-workspace"));

        let conflict_err = BoringCacheError::CacheConflict("tag already claimed".to_string());
        assert!(conflict_err.to_string().contains("tag already claimed"));

        let auth_err = BoringCacheError::AuthenticationFailed("invalid token".to_string());
        assert!(auth_err.to_string().contains("invalid token"));
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
}

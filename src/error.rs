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
    WorkspaceNotFound(String),
    AuthenticationFailed,
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
            BoringCacheError::WorkspaceNotFound(workspace) => {
                write!(f, "Workspace '{workspace}' not found")
            }
            BoringCacheError::AuthenticationFailed => write!(f, "Authentication failed"),
        }
    }
}

impl std::error::Error for BoringCacheError {}

impl From<std::io::Error> for BoringCacheError {
    fn from(err: std::io::Error) -> Self {
        BoringCacheError::IoError(err.to_string())
    }
}

impl From<reqwest::Error> for BoringCacheError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_connect() {
            BoringCacheError::ConnectionError(
                "❌ Cannot connect to BoringCache server. Please check:\n\
                 • Is the server running? (Start with: cd web && rails server)\n\
                 • Is the API URL correct? (Check with: boringcache config)\n\
                 • Is there a firewall blocking the connection?"
                    .to_string(),
            )
        } else if err.is_timeout() {
            BoringCacheError::ConnectionError(
                "⏱️  Connection timed out. The server might be overloaded or unreachable."
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

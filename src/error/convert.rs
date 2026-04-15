use crate::error::BoringCacheError;

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

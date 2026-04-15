use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictMetadata {
    pub current_version: Option<String>,
    pub current_cache_entry_id: Option<String>,
    pub current_tag: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
                write!(f, "Authentication failed: {msg}")
            }
        }
    }
}

impl std::error::Error for BoringCacheError {}

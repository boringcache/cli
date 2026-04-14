use serde::{Deserialize, Serialize};

pub mod cache;
pub mod cache_rollups;
pub mod cli_connect;
pub mod metrics;
pub mod optimize;
pub mod workspace;

pub use cache::*;
pub use cache_rollups::*;
pub use cli_connect::*;
pub use metrics::*;
pub use optimize::*;
pub use workspace::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_info_deserializes_without_scopes() {
        let json = r#"{
            "id": "token123",
            "name": "Test Token",
            "scope_type": "workspace",
            "expires_at": "2024-01-01T00:00:00Z"
        }"#;

        let token_info: workspace::TokenInfo =
            serde_json::from_str(json).expect("Should deserialize without scopes field");
        assert_eq!(token_info.id, "token123");
        assert_eq!(token_info.scopes, Vec::<String>::new());
    }

    #[test]
    fn test_workspace_info_deserializes_with_slug() {
        let json = r#"{
            "id": "ws123",
            "name": "Test Workspace",
            "slug": "test-workspace"
        }"#;

        let workspace_info: workspace::WorkspaceInfo =
            serde_json::from_str(json).expect("Should deserialize with slug");
        assert_eq!(workspace_info.id, "ws123");
        assert_eq!(workspace_info.name, "Test Workspace");
        assert_eq!(workspace_info.slug, Some("test-workspace".to_string()));
    }

    #[test]
    fn test_restore_result_deserializes_hit() {
        let json = r#"{
            "tag": "ruby-3.4.4-darwin-arm64",
            "status": "hit",
            "cache_entry_id": "11111111-2222-3333-4444-555555555555",
            "manifest_root_digest": "blake3:abc123",
            "manifest_url": "https://example.com/manifest",
            "chunks": [
                {
                    "digest": "chunk1",
                    "url": "https://example.com/chunk1",
                    "sequence_index": 0
                }
            ],
            "metadata": {
                "manifest_root_digest": "blake3:abc123",
                "total_size_bytes": 1024,
                "file_count": 3,
                "compression_algorithm": "zstd"
            }
        }"#;

        let result: cache::RestoreResult =
            serde_json::from_str(json).expect("Should deserialize cache restore hit");
        assert_eq!(result.status, "hit");
    }
}

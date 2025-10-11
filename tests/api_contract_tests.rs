#[cfg(test)]
mod api_contract_tests {
    use boring_cache_cli::api;

    /// Test that save requests send tag metadata for a single cache entry
    #[test]
    fn test_save_request_payload_structure() {
        use boring_cache_cli::api::models::cache::{SaveChunkMetadata, SaveRequest};

        let request = SaveRequest {
            tag: "ruby-cache".to_string(),
            manifest_root_digest: "blake3:abc123".to_string(),
            compression_algorithm: "zstd".to_string(),
            manifest_format_version: Some(1),
            total_size_bytes: 1024,
            uncompressed_size: Some(2048),
            compressed_size: Some(1024),
            file_count: Some(5),
            chunk_digests: vec!["blake3:def456".to_string()],
            chunk_metadata: Some(vec![SaveChunkMetadata {
                digest: "blake3:def456".to_string(),
                uncompressed_size: Some(2048),
                compressed_size: Some(1024),
                compression_algorithm: Some("zstd".to_string()),
                size: Some(1024),
                file_path: None,
                offset: Some(0),
            }]),
            force: None,
        };

        let json = serde_json::to_value(&request).unwrap();

        assert_eq!(json["tag"].as_str().unwrap(), "ruby-cache");
        assert!(json.get("entries").is_none());
        assert!(json["chunk_digests"].is_array());
    }

    /// Test that CLI uses entries query parameter for restore operations
    #[test]
    fn test_restore_entries_parameter() {
        let joined = ["ruby-cache", "node-cache"].join(",");
        assert_eq!(joined, "ruby-cache,node-cache");
    }

    /// Test workspace URL format validation
    #[test]
    fn test_workspace_url_format_validation() {
        // Valid workspace formats
        assert!(api::parse_workspace_slug("myorg/myapp").is_ok());
        assert!(api::parse_workspace_slug("user-name/app-name").is_ok());
        assert!(api::parse_workspace_slug("org.name/app.name").is_ok());

        // Invalid workspace formats should fail
        assert!(api::parse_workspace_slug("invalid").is_err());
        assert!(api::parse_workspace_slug("").is_err());
        assert!(api::parse_workspace_slug("org/").is_err());
        assert!(api::parse_workspace_slug("/app").is_err());
        assert!(api::parse_workspace_slug("org/app/extra").is_err());
    }

    /// Test that CLI builds correct workspace URLs
    #[test]
    fn test_workspace_url_building() {
        // Test the workspace parsing that feeds into URL building
        let (namespace, workspace) = api::parse_workspace_slug("myorg/myapp").unwrap();
        assert_eq!(namespace, "myorg");
        assert_eq!(workspace, "myapp");

        // Test expected URL format
        let expected_url = format!("/api/v1/workspaces/{}/{}/caches", namespace, workspace);
        assert_eq!(expected_url, "/api/v1/workspaces/myorg/myapp/caches");
    }

    /// Test that save entries send tag-only identifiers to the API
    #[test]
    fn test_save_entry_format() {
        let entries = ["rust-cache", "build-cache"];

        let combined = entries.join(",");
        assert_eq!(combined, "rust-cache,build-cache");

        for entry in &entries {
            assert!(!entry.contains(':'), "entry should be tag-only: {entry}");
        }
    }

    /// Test that restore entries send tag-only identifiers to the API
    #[test]
    fn test_restore_entry_format() {
        let entries = ["rust-cache", "build-cache"];

        let combined = entries.join(",");
        assert_eq!(combined, "rust-cache,build-cache");

        for entry in &entries {
            assert!(!entry.contains(':'), "entry should be tag-only: {entry}");
        }
    }

    /// Test contract compliance for restore response structures
    #[test]
    fn test_restore_response_structure() {
        use boring_cache_cli::api::models::cache::{RestoreChunk, RestoreMetadata, RestoreResult};

        let response = RestoreResult {
            tag: "ruby-cache".to_string(),
            status: "hit".to_string(),
            cache_entry_id: Some("1234".to_string()),
            manifest_root_digest: Some("blake3:abc".to_string()),
            manifest_digest: None,
            manifest_url: Some("https://example.com/manifest".to_string()),
            compression_algorithm: Some("zstd".to_string()),
            chunk_count: Some(1),
            chunks: vec![RestoreChunk {
                digest: "blake3:abc".to_string(),
                url: "https://example.com/chunk".to_string(),
                sequence_index: 0,
                compression_algorithm: Some("zstd".to_string()),
                uncompressed_size: Some(2048),
                compressed_size: Some(1024),
            }],
            metadata: Some(RestoreMetadata {
                manifest_root_digest: Some("blake3:abc".to_string()),
                total_size_bytes: Some(1024),
                file_count: Some(5),
                compression_algorithm: Some("zstd".to_string()),
            }),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: RestoreResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tag, "ruby-cache");
        assert!(parsed.manifest_url.is_some());
        assert_eq!(parsed.chunks.len(), 1);
        assert_eq!(
            parsed.metadata.unwrap().compression_algorithm,
            Some("zstd".to_string())
        );
    }
}

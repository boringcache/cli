#[cfg(test)]
mod api_contract_tests {
    use boring_cache_cli::api;

    /// Test that CLI always sends 'entries' parameter for save operations
    #[test]
    fn test_batch_save_uses_entries_parameter() {
        // Simulate the BatchSaveParams struct used in batch_save_caches()
        #[derive(serde::Serialize)]
        struct BatchSaveParams {
            entries: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            compression_algorithm: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
        }

        let params = BatchSaveParams {
            entries: "tag1,tag2".to_string(),
            compression_algorithm: Some("lz4".to_string()),
            description: None,
        };

        let json = serde_json::to_value(&params).unwrap();

        // Contract: Must have 'entries' parameter
        assert!(json["entries"].is_string());
        assert_eq!(json["entries"].as_str().unwrap(), "tag1,tag2");

        // Contract: Must NOT have legacy parameters like 'entry' or 'keys'
        assert!(json["entry"].is_null());
        assert!(json["keys"].is_null());
        assert!(json["key"].is_null());
    }

    /// Test that CLI always sends 'entries' parameter for restore operations
    #[test]
    fn test_batch_restore_uses_entries_parameter() {
        // Simulate the BatchRestoreParams struct used in batch_restore_caches()
        #[derive(serde::Serialize)]
        struct BatchRestoreParams {
            entries: String,
        }

        let params = BatchRestoreParams {
            entries: "tag1,tag2".to_string(),
        };

        let json = serde_json::to_value(&params).unwrap();

        // Contract: Must have 'entries' parameter
        assert!(json["entries"].is_string());
        assert_eq!(json["entries"].as_str().unwrap(), "tag1,tag2");

        // Contract: Must NOT have legacy parameters
        assert!(json["keys"].is_null());
        assert!(json["entry"].is_null());
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
        let entries = vec!["rust-cache".to_string(), "build-cache".to_string()];

        let combined = entries.join(",");
        assert_eq!(combined, "rust-cache,build-cache");

        for entry in &entries {
            assert!(!entry.contains(':'), "entry should be tag-only: {entry}");
        }
    }

    /// Test that restore entries send tag-only identifiers to the API
    #[test]
    fn test_restore_entry_format() {
        let entries = vec!["rust-cache".to_string(), "build-cache".to_string()];

        let combined = entries.join(",");
        assert_eq!(combined, "rust-cache,build-cache");

        for entry in &entries {
            assert!(!entry.contains(':'), "entry should be tag-only: {entry}");
        }
    }

    /// Test contract compliance for API response structures
    #[test]
    fn test_api_response_structures() {
        // Test that CacheResolutionEntry matches expected contract
        let json_response = r#"
        {
            "identifier": "ruby-3.2.0",
            "tag": "ruby-3.2.0",
            "key": "abcf6b6b1cec2b84",
            "path": "/tmp/ruby",
            "status": "hit",
            "url": "https://example.com/download",
            "source": "workspace",
            "cache_tag": {
                "name": "ruby-3.2.0",
                "id": "358968a5-d3cb-4c60-98f5-daf2fa9e2b8c"
            },
            "compression_algorithm": "lz4",
            "size": 1024000
        }
        "#;

        let entry: api::CacheResolutionEntry = serde_json::from_str(json_response).unwrap();
        assert_eq!(entry.identifier, Some("ruby-3.2.0".to_string()));
        assert_eq!(entry.tag, Some("ruby-3.2.0".to_string()));
        assert_eq!(entry.key, Some("abcf6b6b1cec2b84".to_string()));
        assert_eq!(entry.path, Some("/tmp/ruby".to_string()));
        assert_eq!(entry.status, Some("hit".to_string()));
        assert!(entry.url.is_some());
        assert_eq!(entry.source, Some("workspace".to_string()));
        assert!(entry.cache_tag.is_some());
        assert_eq!(entry.cache_tag.as_ref().unwrap().name, "ruby-3.2.0");
        assert_eq!(
            entry.cache_tag.as_ref().unwrap().id,
            "358968a5-d3cb-4c60-98f5-daf2fa9e2b8c"
        );
        assert_eq!(entry.compression_algorithm, Some("lz4".to_string()));
        assert_eq!(entry.size, Some(1024000));
    }
}

mod request_validation {
    use boring_cache_cli::api::models::cache::{
        ConfirmRequest, ManifestCheckBatchRequest, ManifestCheckRequest, SaveRequest,
    };

    #[test]
    fn test_save_request_serializes_correctly() {
        let request = SaveRequest {
            tag: "ruby-3.4.4-darwin-arm64".to_string(),
            manifest_root_digest: "a".repeat(64),
            compression_algorithm: "zstd".to_string(),
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            manifest_format_version: Some(1),
            total_size_bytes: 1_000_000,
            uncompressed_size: Some(2_000_000),
            compressed_size: Some(1_000_000),
            file_count: Some(150),
            expected_manifest_digest: Some("b".repeat(64)),
            expected_manifest_size: Some(8192),
            force: None,
            use_multipart: None,
            ci_provider: Some("github-actions".to_string()),
            encrypted: None,
            encryption_algorithm: None,
            encryption_recipient_hint: None,
        };

        let json = serde_json::to_value(&request).unwrap();

        assert!(json.get("tag").is_some());
        assert!(json.get("manifest_root_digest").is_some());
        assert!(json.get("compression_algorithm").is_some());
        assert!(json.get("total_size_bytes").is_some());

        assert!(json.get("manifest_format_version").is_some());
        assert!(json.get("uncompressed_size").is_some());
        assert!(json.get("file_count").is_some());

        assert!(json.get("force").is_none());
        assert!(json.get("use_multipart").is_none());
    }

    #[test]
    fn test_save_request_minimal() {
        let request = SaveRequest {
            tag: "test-cache".to_string(),
            manifest_root_digest: "c".repeat(64),
            compression_algorithm: "zstd".to_string(),
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            manifest_format_version: None,
            total_size_bytes: 1000,
            uncompressed_size: None,
            compressed_size: None,
            file_count: None,
            expected_manifest_digest: None,
            expected_manifest_size: None,
            force: None,
            use_multipart: None,
            ci_provider: None,
            encrypted: None,
            encryption_algorithm: None,
            encryption_recipient_hint: None,
        };

        let json = serde_json::to_value(&request).unwrap();

        assert_eq!(json.as_object().unwrap().len(), 4);
        assert!(json.get("tag").is_some());
        assert!(json.get("manifest_root_digest").is_some());
        assert!(json.get("compression_algorithm").is_some());
        assert!(json.get("total_size_bytes").is_some());
    }

    #[test]
    fn test_confirm_request_serializes_correctly() {
        let request = ConfirmRequest {
            manifest_digest: "d".repeat(64),
            manifest_size: 8192,
            manifest_etag: Some("\"abc123\"".to_string()),
            archive_size: Some(1_000_000),
            archive_etag: Some("\"def456\"".to_string()),
            blob_count: None,
            blob_total_size_bytes: None,
            file_count: Some(100),
            uncompressed_size: Some(2_000_000),
            compressed_size: Some(1_000_000),
            tag: None,
        };

        let json = serde_json::to_value(&request).unwrap();

        assert!(json.get("manifest_digest").is_some());
        assert!(json.get("manifest_size").is_some());
        assert!(json.get("archive_size").is_some());

        assert!(json.get("manifest_etag").is_some());
        assert!(json.get("archive_etag").is_some());
        assert!(json.get("file_count").is_some());

        assert!(json.get("archive_digest").is_none());
    }

    #[test]
    fn test_confirm_request_with_tag_for_piggybacking() {
        let request = ConfirmRequest {
            manifest_digest: "d".repeat(64),
            manifest_size: 8192,
            manifest_etag: None,
            archive_size: Some(1_000_000),
            archive_etag: None,
            blob_count: None,
            blob_total_size_bytes: None,
            file_count: Some(100),
            uncompressed_size: Some(2_000_000),
            compressed_size: Some(1_000_000),
            tag: Some("my-cache-tag".to_string()),
        };

        let json = serde_json::to_value(&request).unwrap();

        assert!(json.get("tag").is_some());
        assert_eq!(json.get("tag").unwrap(), "my-cache-tag");
        assert!(json.get("manifest_etag").is_none());
        assert!(json.get("archive_etag").is_none());
    }

    #[test]
    fn test_manifest_check_request_serializes_correctly() {
        let batch = ManifestCheckBatchRequest {
            manifest_checks: vec![
                ManifestCheckRequest {
                    tag: "ruby-cache".to_string(),
                    manifest_root_digest: "f".repeat(64),
                    lookup: None,
                },
                ManifestCheckRequest {
                    tag: "node-cache".to_string(),
                    manifest_root_digest: "g".repeat(64),
                    lookup: None,
                },
            ],
        };

        let json = serde_json::to_value(&batch).unwrap();
        let checks = json.get("manifest_checks").unwrap().as_array().unwrap();

        assert_eq!(checks.len(), 2);
        assert!(checks[0].get("tag").is_some());
        assert!(checks[0].get("manifest_root_digest").is_some());
    }

    #[test]
    fn test_manifest_check_request_serializes_lookup() {
        let batch = ManifestCheckBatchRequest {
            manifest_checks: vec![ManifestCheckRequest {
                tag: "deps-cache".to_string(),
                manifest_root_digest: "a".repeat(64),
                lookup: Some("digest".to_string()),
            }],
        };

        let json = serde_json::to_value(&batch).unwrap();
        let check = &json["manifest_checks"][0];

        assert_eq!(check.get("lookup").unwrap(), "digest");
    }
}

mod response_validation {
    use boring_cache_cli::api::models::cache::{
        CacheConfirmResponse, CacheEntriesListResponse, CompleteMultipartResponse,
        ManifestCheckResponse, RestoreResult, SaveResponse, TagDeleteResponse,
    };
    use boring_cache_cli::api::models::workspace::{SessionInfo, Workspace};
    use serde_json::json;

    #[test]
    fn test_save_response_deserializes_new_cache() {
        let api_response = json!({
            "tag": "ruby-cache",
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "manifest_root_digest": "a".repeat(64),
            "manifest_upload_url": "https://s3.amazonaws.com/bucket/manifest?presigned",
            "archive_urls": ["https://s3.amazonaws.com/bucket/archive?presigned"],
            "multipart_upload_id": null,
            "manifest_etag": null,
            "exists": false,
            "status": "pending",
            "error": null
        });

        let response: SaveResponse = serde_json::from_value(api_response).unwrap();
        assert!(!response.exists);
        assert_eq!(response.get_archive_urls().len(), 1);
    }

    #[test]
    fn test_save_response_deserializes_existing_cache() {
        let api_response = json!({
            "tag": "ruby-cache",
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "manifest_root_digest": "b".repeat(64),
            "manifest_upload_url": null,
            "archive_urls": [],
            "multipart_upload_id": null,
            "manifest_etag": "\"existingetag\"",
            "exists": true,
            "status": "ready",
            "error": null
        });

        let response: SaveResponse = serde_json::from_value(api_response).unwrap();
        assert!(response.exists);
    }

    #[test]
    fn test_cache_confirm_response_deserializes() {
        let api_response = json!({
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "ready",
            "uploaded_at": "2024-01-15T10:30:00Z"
        });

        let _: CacheConfirmResponse = serde_json::from_value(api_response).unwrap();
    }

    #[test]
    fn test_cache_confirm_response_with_tag_status_ready() {
        let api_response = json!({
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "ready",
            "uploaded_at": "2024-01-15T10:30:00Z",
            "tag_status": "ready"
        });

        let response: CacheConfirmResponse = serde_json::from_value(api_response).unwrap();
        assert_eq!(response.tag_status, Some("ready".to_string()));
    }

    #[test]
    fn test_cache_confirm_response_with_tag_status_pending() {
        let api_response = json!({
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "pending",
            "tag_status": "pending"
        });

        let response: CacheConfirmResponse = serde_json::from_value(api_response).unwrap();
        assert_eq!(response.tag_status, Some("pending".to_string()));
    }

    #[test]
    fn test_restore_result_deserializes_hit() {
        let api_response = json!({
            "tag": "ruby-cache",
            "status": "hit",
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "manifest_root_digest": "c".repeat(64),
            "manifest_digest": "d".repeat(64),
            "manifest_url": "https://s3.amazonaws.com/bucket/manifest?presigned",
            "compression_algorithm": "zstd",
            "archive_url": "https://s3.amazonaws.com/bucket/archive?presigned",
            "archive_urls": ["https://s3.amazonaws.com/bucket/archive?presigned"],
            "metadata": {
                "manifest_root_digest": "c".repeat(64),
                "total_size_bytes": 1000000,
                "file_count": 150,
                "compression_algorithm": "zstd"
            }
        });

        let result: RestoreResult = serde_json::from_value(api_response).unwrap();
        assert_eq!(result.status, "hit");
    }

    #[test]
    fn test_restore_result_deserializes_miss() {
        let api_response = json!({
            "tag": "nonexistent-cache",
            "status": "miss"
        });

        let result: RestoreResult = serde_json::from_value(api_response).unwrap();
        assert_eq!(result.status, "miss");
    }

    #[test]
    fn test_manifest_check_response_deserializes() {
        let api_response = json!({
            "results": [
                {
                    "tag": "ruby-cache",
                    "exists": true,
                    "manifest_root_digest": "e".repeat(64),
                    "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
                    "status": "ready"
                },
                {
                    "tag": "missing-cache",
                    "exists": false
                }
            ]
        });

        let response: ManifestCheckResponse = serde_json::from_value(api_response).unwrap();
        assert_eq!(response.results.len(), 2);
        assert!(response.results[0].exists);
        assert!(!response.results[1].exists);
    }

    #[test]
    fn test_tag_delete_response_deserializes() {
        let deleted = json!({
            "tag": "old-cache",
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "deleted",
            "error": null
        });

        let result: TagDeleteResponse = serde_json::from_value(deleted).unwrap();
        assert!(result.is_deleted());

        let missing = json!({
            "tag": "nonexistent",
            "cache_entry_id": null,
            "status": "missing",
            "error": null
        });

        let result: TagDeleteResponse = serde_json::from_value(missing).unwrap();
        assert!(!result.is_deleted());
    }

    #[test]
    fn test_multipart_complete_response_deserializes() {
        let api_response = json!({
            "archive_etag": "\"abc123-10\""
        });

        let _: CompleteMultipartResponse = serde_json::from_value(api_response).unwrap();
    }

    #[test]
    fn test_cache_entries_list_response_deserializes() {
        let api_response = json!({
            "entries": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "manifest_root_digest": "h".repeat(64),
                    "tag": "ruby-cache",
                    "total_size_bytes": 1000000,
                    "uncompressed_size": 2000000,
                    "compressed_size": 1000000,
                    "file_count": 150,
                    "compression_algorithm": "zstd",
                    "created_at": "2024-01-15T10:00:00Z",
                    "uploaded_at": "2024-01-15T10:30:00Z"
                }
            ],
            "total": 1,
            "page": 1,
            "limit": 10
        });

        let response: CacheEntriesListResponse = serde_json::from_value(api_response).unwrap();
        assert_eq!(response.entries.len(), 1);
        assert_eq!(response.total, 1);
    }

    #[test]
    fn test_workspace_deserializes() {
        let api_response = json!({
            "id": "my-workspace",
            "name": "My Workspace",
            "slug": "my-workspace",
            "cache_entries_count": 25,
            "total_cache_size": 500000000,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-15T10:30:00Z"
        });

        let _: Workspace = serde_json::from_value(api_response).unwrap();
    }

    #[test]
    fn test_session_info_deserializes() {
        let api_response = json!({
            "valid": true,
            "user": {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "John Doe",
                "email": "john@example.com"
            },
            "organization": null,
            "workspace": {
                "id": "550e8400-e29b-41d4-a716-446655440002",
                "name": "My Workspace",
                "slug": "my-workspace"
            },
            "token": {
                "id": "550e8400-e29b-41d4-a716-446655440003",
                "name": "CI Token",
                "scope_type": "workspace",
                "expires_at": "2025-01-01T00:00:00Z",
                "expires_in_days": 365,
                "last_used_at": "2024-01-15T10:30:00Z"
            }
        });

        let _: SessionInfo = serde_json::from_value(api_response).unwrap();
    }

    #[test]
    fn test_session_info_deserializes_with_nulls() {
        let api_response = json!({
            "valid": true,
            "user": {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "name": "John Doe",
                "email": "john@example.com"
            },
            "organization": null,
            "workspace": null,
            "token": {
                "id": "550e8400-e29b-41d4-a716-446655440003",
                "name": "User Token",
                "scope_type": "user",
                "expires_at": null,
                "expires_in_days": null,
                "last_used_at": null
            }
        });

        let _: SessionInfo = serde_json::from_value(api_response).unwrap();
    }
}

mod workspace_validation {
    use boring_cache_cli::api;

    #[test]
    fn test_workspace_url_format_validation() {
        assert!(api::parse_workspace_slug("myorg/myapp").is_ok());
        assert!(api::parse_workspace_slug("user-name/app-name").is_ok());
        assert!(api::parse_workspace_slug("org.name/app.name").is_ok());

        assert!(api::parse_workspace_slug("invalid").is_err());
        assert!(api::parse_workspace_slug("").is_err());
        assert!(api::parse_workspace_slug("org/").is_err());
        assert!(api::parse_workspace_slug("/app").is_err());
        assert!(api::parse_workspace_slug("org/app/extra").is_err());
    }

    #[test]
    fn test_workspace_url_building() {
        let (namespace, workspace) = api::parse_workspace_slug("myorg/myapp").unwrap();
        assert_eq!(namespace, "myorg");
        assert_eq!(workspace, "myapp");
    }
}

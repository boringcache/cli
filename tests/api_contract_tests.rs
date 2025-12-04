//! OpenAPI Contract Validation Tests
//!
//! These tests validate that CLI types exactly match the OpenAPI specification.
//! The OpenAPI spec (openapi.json) is the single source of truth for the API contract.
//!
//! Test categories:
//! 1. Request validation - CLI request payloads match OpenAPI request schemas
//! 2. Response validation - CLI can deserialize all valid API responses
//! 3. Schema compliance - CLI types serialize to valid JSON per OpenAPI schemas

use jsonschema::Validator;
use serde_json::{json, Value};
use std::fs;

/// Load the OpenAPI spec from the project root
fn load_openapi_spec() -> Value {
    let spec_path = concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json");
    let content = fs::read_to_string(spec_path)
        .expect("openapi.json not found. Copy from web/public/openapi.json to cli/openapi.json");
    serde_json::from_str(&content).expect("Failed to parse openapi.json")
}

/// Extract a schema from the OpenAPI spec by name
fn get_schema(spec: &Value, schema_name: &str) -> Value {
    let schema = spec["components"]["schemas"][schema_name].clone();
    if schema.is_null() {
        panic!("Schema '{}' not found in OpenAPI spec", schema_name);
    }

    // Build a self-contained schema with $defs for references
    let mut full_schema = schema.clone();

    // Add all component schemas as $defs for reference resolution
    if let Some(schemas) = spec["components"]["schemas"].as_object() {
        let defs: Value = schemas.clone().into_iter().collect();
        full_schema["$defs"] = defs;
    }

    // Rewrite $ref paths from #/components/schemas/X to #/$defs/X
    rewrite_refs(&mut full_schema);

    full_schema
}

/// Recursively rewrite $ref paths for local resolution
fn rewrite_refs(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(ref_val) = map.get_mut("$ref") {
                if let Some(s) = ref_val.as_str() {
                    if s.starts_with("#/components/schemas/") {
                        *ref_val = Value::String(s.replace("#/components/schemas/", "#/$defs/"));
                    }
                }
            }
            for v in map.values_mut() {
                rewrite_refs(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                rewrite_refs(v);
            }
        }
        _ => {}
    }
}

/// Compile a JSON schema for validation
fn compile_schema(schema: &Value) -> Validator {
    jsonschema::validator_for(schema).expect("Failed to compile JSON schema")
}

/// Validate a value against a schema and return detailed errors
fn validate_against_schema(validator: &Validator, value: &Value, context: &str) {
    if !validator.is_valid(value) {
        let error_messages: Vec<String> = validator
            .iter_errors(value)
            .map(|e| format!("  - {}: {}", e.instance_path, e))
            .collect();
        panic!(
            "Schema validation failed for {}:\n{}\n\nValue:\n{}",
            context,
            error_messages.join("\n"),
            serde_json::to_string_pretty(value).unwrap()
        );
    }
}

// =============================================================================
// REQUEST SCHEMA VALIDATION
// These tests verify CLI request payloads match OpenAPI request body schemas
// =============================================================================

mod request_validation {
    use super::*;
    use boring_cache_cli::api::models::cache::{
        ConfirmRequest, ManifestCheckBatchRequest, ManifestCheckRequest, SaveRequest,
    };
    use boring_cache_cli::api::models::metrics::MetricsParams;

    #[test]
    fn test_save_request_matches_cache_entry_create_schema() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "CacheEntryCreate");
        let compiled = compile_schema(&schema);

        // Create a full SaveRequest with all fields
        let request = SaveRequest {
            tag: "ruby-3.4.4-darwin-arm64".to_string(),
            manifest_root_digest: "a".repeat(64),
            compression_algorithm: "zstd".to_string(),
            manifest_format_version: Some(1),
            total_size_bytes: 1_000_000,
            uncompressed_size: Some(2_000_000),
            compressed_size: Some(1_000_000),
            file_count: Some(150),
            expected_manifest_digest: Some("b".repeat(64)),
            expected_manifest_size: Some(8192),
            force: None,
            use_multipart: None,
        };

        let json = serde_json::to_value(&request).unwrap();
        validate_against_schema(&compiled, &json, "SaveRequest -> CacheEntryCreate");
    }

    #[test]
    fn test_save_request_minimal_matches_schema() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "CacheEntryCreate");
        let compiled = compile_schema(&schema);

        // Minimal required fields only
        let request = SaveRequest {
            tag: "test-cache".to_string(),
            manifest_root_digest: "c".repeat(64),
            compression_algorithm: "zstd".to_string(),
            manifest_format_version: None,
            total_size_bytes: 1000,
            uncompressed_size: None,
            compressed_size: None,
            file_count: None,
            expected_manifest_digest: None,
            expected_manifest_size: None,
            force: None,
            use_multipart: None,
        };

        let json = serde_json::to_value(&request).unwrap();
        validate_against_schema(
            &compiled,
            &json,
            "SaveRequest (minimal) -> CacheEntryCreate",
        );
    }

    #[test]
    fn test_confirm_request_matches_single_upload_confirm_schema() {
        let spec = load_openapi_spec();
        // The API expects { cache: { ... } } wrapper
        let schema = get_schema(&spec, "SingleUploadConfirm");
        let compiled = compile_schema(&schema);

        let request = ConfirmRequest {
            manifest_digest: "d".repeat(64),
            manifest_size: 8192,
            manifest_etag: Some("\"abc123\"".to_string()),
            archive_digest: "e".repeat(64),
            archive_size: 1_000_000,
            archive_etag: Some("\"def456\"".to_string()),
            file_count: Some(100),
            uncompressed_size: Some(2_000_000),
            compressed_size: Some(1_000_000),
        };

        // Wrap in { cache: ... } as API expects
        let wrapped = json!({ "cache": serde_json::to_value(&request).unwrap() });
        validate_against_schema(&compiled, &wrapped, "ConfirmRequest -> SingleUploadConfirm");
    }

    #[test]
    fn test_manifest_check_request_matches_schema() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "ManifestCheckRequest");
        let compiled = compile_schema(&schema);

        let batch = ManifestCheckBatchRequest {
            manifest_checks: vec![
                ManifestCheckRequest {
                    tag: "ruby-cache".to_string(),
                    manifest_root_digest: "f".repeat(64),
                },
                ManifestCheckRequest {
                    tag: "node-cache".to_string(),
                    manifest_root_digest: "g".repeat(64),
                },
            ],
        };

        let json = serde_json::to_value(&batch).unwrap();
        validate_against_schema(
            &compiled,
            &json,
            "ManifestCheckBatchRequest -> ManifestCheckRequest",
        );
    }

    #[test]
    fn test_metrics_submission_matches_schema() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "MetricSubmission");
        let compiled = compile_schema(&schema);

        let metrics = MetricsParams {
            operation_type: "save".to_string(),
            cache_path: Some("/path/to/cache".to_string()),
            content_hash: Some("h".repeat(64)),
            total_duration: 5000,
            archive_duration: Some(1000),
            upload_duration: Some(3000),
            download_duration: None,
            extract_duration: None,
            confirm_duration: Some(500),
            uncompressed_size: Some(10_000_000),
            compressed_size: Some(5_000_000),
            compression_ratio: Some(0.5),
            file_count: Some(500),
            upload_speed_mbps: Some(100.5),
            download_speed_mbps: None,
            cache_age_hours: None,
            error_message: None,
            benchmark_compression_ratio: Some(0.45),
            compression_duration: Some(800),
            predicted_time_ms: Some(4500),
            prediction_accuracy: Some(0.9),
            tags: Some(vec!["ruby".to_string(), "deps".to_string()]),
            compression_algorithm: Some("zstd".to_string()),
            cpu_cores: Some(8),
            cpu_load_percent: Some(45.5),
            total_memory_gb: Some(16.0),
            available_memory_gb: Some(8.5),
            memory_strategy: Some("streaming".to_string()),
            disk_type: Some("ssd".to_string()),
            disk_speed_estimate_mb_s: Some(500.0),
            concurrent_operations: Some(4),
            buffer_size_mb: Some(64),
            part_size_mb: Some(100),
            concurrency_level: Some(4),
            streaming_enabled: Some(true),
            compression_level: Some(3),
            compression_threads: Some(4),
            benchmark_throughput_mb_s: Some(200.0),
            bandwidth_probe_mb_s: Some(150.0),
            multipart_threshold_mb: Some(50),
            part_count: Some(10),
            retry_count: Some(0),
            transfer_size: Some(5_000_000),
            cache_efficiency: Some(0.85),
        };

        let json = serde_json::to_value(&metrics).unwrap();
        validate_against_schema(&compiled, &json, "MetricsParams -> MetricSubmission");
    }
}

// =============================================================================
// RESPONSE SCHEMA VALIDATION
// These tests verify CLI can correctly deserialize all valid API responses
// =============================================================================

mod response_validation {
    use super::*;
    use boring_cache_cli::api::models::cache::{
        CacheConfirmResponse, CacheEntriesListResponse, CompleteMultipartResponse,
        ManifestCheckResponse, RestoreResult, SaveResponse, TagDeleteResponse,
    };
    use boring_cache_cli::api::models::workspace::{SessionInfo, Workspace};

    #[test]
    fn test_cli_deserializes_single_upload_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "SingleUploadResponse");
        let compiled = compile_schema(&schema);

        // API response for new cache creation
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

        // Validate API response matches schema
        validate_against_schema(&compiled, &api_response, "SingleUploadResponse (new)");

        // Verify CLI can deserialize it
        let _: SaveResponse = serde_json::from_value(api_response)
            .expect("CLI SaveResponse should deserialize valid SingleUploadResponse");
    }

    #[test]
    fn test_cli_deserializes_single_upload_response_existing() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "SingleUploadResponse");
        let compiled = compile_schema(&schema);

        // API response when cache already exists
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

        validate_against_schema(&compiled, &api_response, "SingleUploadResponse (existing)");

        let response: SaveResponse = serde_json::from_value(api_response)
            .expect("CLI SaveResponse should deserialize existing cache response");
        assert!(response.exists);
    }

    #[test]
    fn test_cli_deserializes_cache_confirm_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "CacheConfirmResponse");
        let compiled = compile_schema(&schema);

        let api_response = json!({
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "ready",
            "uploaded_at": "2024-01-15T10:30:00Z"
        });

        validate_against_schema(&compiled, &api_response, "CacheConfirmResponse");

        let _: CacheConfirmResponse = serde_json::from_value(api_response)
            .expect("CLI CacheConfirmResponse should deserialize valid response");
    }

    #[test]
    fn test_cli_deserializes_cache_restore_result() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "CacheRestoreResult");
        let compiled = compile_schema(&schema);

        // Cache hit response
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

        validate_against_schema(&compiled, &api_response, "CacheRestoreResult (hit)");

        let result: RestoreResult = serde_json::from_value(api_response)
            .expect("CLI RestoreResult should deserialize cache hit");
        assert_eq!(result.status, "hit");
    }

    #[test]
    fn test_cli_deserializes_cache_restore_miss() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "CacheRestoreResult");
        let compiled = compile_schema(&schema);

        // Cache miss response - API omits optional fields rather than sending null
        let api_response = json!({
            "tag": "nonexistent-cache",
            "status": "miss"
        });

        validate_against_schema(&compiled, &api_response, "CacheRestoreResult (miss)");

        let result: RestoreResult = serde_json::from_value(api_response)
            .expect("CLI RestoreResult should deserialize cache miss");
        assert_eq!(result.status, "miss");
    }

    #[test]
    fn test_cli_deserializes_manifest_check_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "ManifestCheckResponse");
        let compiled = compile_schema(&schema);

        let api_response = json!({
            "results": [
                {
                    "tag": "ruby-cache",
                    "exists": true,
                    "manifest_root_digest": "e".repeat(64),
                    "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
                    "content_hash": "f".repeat(64),
                    "manifest_digest": "g".repeat(64),
                    "manifest_url": "https://s3.amazonaws.com/manifest",
                    "compression_algorithm": "zstd",
                    "archive_url": "https://s3.amazonaws.com/archive",
                    "archive_urls": ["https://s3.amazonaws.com/archive"],
                    "size": 1000000,
                    "uncompressed_size": 2000000,
                    "compressed_size": 1000000,
                    "uploaded_at": "2024-01-15T10:30:00Z",
                    "status": "ready"
                },
                {
                    "tag": "missing-cache",
                    "exists": false
                }
            ]
        });

        validate_against_schema(&compiled, &api_response, "ManifestCheckResponse");

        let response: ManifestCheckResponse = serde_json::from_value(api_response)
            .expect("CLI ManifestCheckResponse should deserialize valid response");
        assert_eq!(response.results.len(), 2);
        assert!(response.results[0].exists);
        assert!(!response.results[1].exists);
    }

    #[test]
    fn test_cli_deserializes_tag_delete_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "TagDeleteResponse");
        let compiled = compile_schema(&schema);

        // Successful deletion
        let deleted = json!({
            "tag": "old-cache",
            "cache_entry_id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "deleted",
            "error": null
        });

        validate_against_schema(&compiled, &deleted, "TagDeleteResponse (deleted)");

        let result: TagDeleteResponse = serde_json::from_value(deleted)
            .expect("CLI TagDeleteResponse should deserialize deletion");
        assert!(result.is_deleted());

        // Missing tag
        let missing = json!({
            "tag": "nonexistent",
            "cache_entry_id": null,
            "status": "missing",
            "error": null
        });

        validate_against_schema(&compiled, &missing, "TagDeleteResponse (missing)");

        let result: TagDeleteResponse = serde_json::from_value(missing)
            .expect("CLI TagDeleteResponse should deserialize missing");
        assert!(!result.is_deleted());
    }

    #[test]
    fn test_cli_deserializes_multipart_complete_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "MultipartCompleteResponse");
        let compiled = compile_schema(&schema);

        let api_response = json!({
            "archive_etag": "\"abc123-10\""
        });

        validate_against_schema(&compiled, &api_response, "MultipartCompleteResponse");

        let _: CompleteMultipartResponse = serde_json::from_value(api_response)
            .expect("CLI CompleteMultipartResponse should deserialize valid response");
    }

    #[test]
    fn test_cli_deserializes_cache_entries_list_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "CacheEntriesListResponse");
        let compiled = compile_schema(&schema);

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

        validate_against_schema(&compiled, &api_response, "CacheEntriesListResponse");

        let response: CacheEntriesListResponse = serde_json::from_value(api_response)
            .expect("CLI CacheEntriesListResponse should deserialize valid response");
        assert_eq!(response.entries.len(), 1);
        assert_eq!(response.total, 1);
    }

    #[test]
    fn test_cli_deserializes_workspace_summary() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "WorkspaceSummary");
        let compiled = compile_schema(&schema);

        let api_response = json!({
            "id": "my-workspace",
            "name": "My Workspace",
            "slug": "my-workspace",
            "cache_entries_count": 25,
            "total_cache_size": 500000000,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-15T10:30:00Z"
        });

        validate_against_schema(&compiled, &api_response, "WorkspaceSummary");

        let _: Workspace = serde_json::from_value(api_response)
            .expect("CLI Workspace should deserialize WorkspaceSummary");
    }

    #[test]
    fn test_cli_deserializes_session_response() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "SessionResponse");
        let compiled = compile_schema(&schema);

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

        validate_against_schema(&compiled, &api_response, "SessionResponse");

        let _: SessionInfo = serde_json::from_value(api_response)
            .expect("CLI SessionInfo should deserialize SessionResponse");
    }

    #[test]
    fn test_cli_deserializes_session_response_with_nulls() {
        let spec = load_openapi_spec();
        let schema = get_schema(&spec, "SessionResponse");
        let compiled = compile_schema(&schema);

        // Response with nullable fields as null
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

        validate_against_schema(&compiled, &api_response, "SessionResponse (with nulls)");

        let _: SessionInfo = serde_json::from_value(api_response)
            .expect("CLI SessionInfo should deserialize SessionResponse with nulls");
    }
}

// =============================================================================
// LEGACY TESTS - Preserved from original file
// =============================================================================

mod legacy_tests {
    use boring_cache_cli::api;

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

    #[test]
    fn test_workspace_url_building() {
        let (namespace, workspace) = api::parse_workspace_slug("myorg/myapp").unwrap();
        assert_eq!(namespace, "myorg");
        assert_eq!(workspace, "myapp");

        let expected_url = format!("/api/v1/workspaces/{}/{}/caches", namespace, workspace);
        assert_eq!(expected_url, "/api/v1/workspaces/myorg/myapp/caches");
    }
}

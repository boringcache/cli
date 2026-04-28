use super::*;
use crate::api::cache;
use crate::test_env;
use mockito::Matcher;
use serde_json::json;
use std::net::TcpListener;

fn networking_available() -> bool {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

fn digest_for(index: usize) -> String {
    format!("sha256:{index:064x}")
}

#[test]
fn test_url_building() {
    super::ensure_crypto_provider();
    let client = ApiClient {
        client: Client::new(),
        transfer_client: Client::new(),
        base_url: "https://api.example.com".to_string(),
        v1_base_url: "https://api.example.com/v1".to_string(),
        v2_base_url: "https://api.example.com/v2".to_string(),
        auth_token: None,
        capabilities: Arc::new(RwLock::new(None)),
    };

    assert_eq!(
        client.build_url("test/endpoint"),
        "https://api.example.com/test/endpoint"
    );

    assert_eq!(
        client.build_url("/test/endpoint"),
        "https://api.example.com/test/endpoint"
    );
}

#[test]
fn test_api_batch_concurrency_is_bounded() {
    assert_eq!(api_batch_concurrency_for_context(1, 4, false), 1);
    assert_eq!(api_batch_concurrency_for_context(4, 4, false), 4);
    assert_eq!(api_batch_concurrency_for_context(32, 4, false), 4);
    assert_eq!(api_batch_concurrency_for_context(32, 4, true), 8);
    assert_eq!(api_batch_concurrency_for_context(32, 2, true), 4);
}

#[test]
fn test_blob_batch_maxes_use_fixed_defaults() {
    assert_eq!(blob_check_batch_max(), BLOB_CHECK_BATCH_MAX);
    assert_eq!(blob_url_batch_max(), BLOB_URL_BATCH_MAX);
}

#[test]
fn test_blob_batch_concurrency_uses_machine_governor() {
    assert_eq!(blob_check_batch_concurrency(0), 1);
    assert_eq!(blob_url_batch_concurrency(0), 1);
    assert_eq!(blob_check_batch_concurrency(1), 1);
    assert_eq!(
        blob_check_batch_concurrency(10),
        api_batch_concurrency(10).clamp(1, 10)
    );
    assert_eq!(
        blob_url_batch_concurrency(10),
        api_batch_concurrency(10).clamp(1, 10)
    );
}

#[test]
fn test_transfer_http2_enabled_defaults_true() {
    let _guard = test_env::lock();

    test_env::remove_var("BORINGCACHE_TRANSFER_HTTP2");
    assert!(transfer_http2_enabled());
}

#[test]
fn test_transfer_http2_enabled_respects_false_values() {
    let _guard = test_env::lock();

    for value in ["0", "false", "FALSE", "no", "off"] {
        test_env::set_var("BORINGCACHE_TRANSFER_HTTP2", value);
        assert!(!transfer_http2_enabled(), "value {value} should disable h2");
    }
    test_env::remove_var("BORINGCACHE_TRANSFER_HTTP2");
}

#[test]
fn test_transfer_http2_enabled_respects_true_and_unknown_values() {
    let _guard = test_env::lock();

    for value in ["1", "true", "TRUE", "yes", "on", "unexpected"] {
        test_env::set_var("BORINGCACHE_TRANSFER_HTTP2", value);
        assert!(transfer_http2_enabled(), "value {value} should enable h2");
    }
    test_env::remove_var("BORINGCACHE_TRANSFER_HTTP2");
}

#[test]
fn test_derive_api_base_urls_from_v1() {
    let (v1, v2) = derive_api_base_urls("https://api.example.com/v1");
    assert_eq!(v1, "https://api.example.com/v1");
    assert_eq!(v2, "https://api.example.com/v2");
}

#[test]
fn test_derive_api_base_urls_from_v2() {
    let (v1, v2) = derive_api_base_urls("https://api.example.com/v2");
    assert_eq!(v1, "https://api.example.com/v1");
    assert_eq!(v2, "https://api.example.com/v2");
}

#[test]
fn test_derive_api_base_urls_from_unversioned_remote() {
    let (v1, v2) = derive_api_base_urls("https://api.example.com");
    assert_eq!(v1, "https://api.example.com/v1");
    assert_eq!(v2, "https://api.example.com/v2");
}

#[test]
fn test_derive_api_base_urls_from_unversioned_localhost() {
    let (v1, v2) = derive_api_base_urls("http://127.0.0.1:1234");
    assert_eq!(v1, "http://127.0.0.1:1234/v1");
    assert_eq!(v2, "http://127.0.0.1:1234/v2");
}

#[test]
fn test_derive_api_base_urls_from_empty_input_uses_default_base() {
    let (v1, v2) = derive_api_base_urls("   ");
    assert_eq!(v1, "https://api.boringcache.com/v1");
    assert_eq!(v2, "https://api.boringcache.com/v2");
}

#[test]
fn test_default_base_url_matches_config() {
    let _guard = test_env::lock();

    // Isolate from user config by using a temp HOME directory
    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());
    test_env::remove_var("BORINGCACHE_API_URL");

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize without BORINGCACHE_API_URL or config file");

    // Restore original HOME
    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }

    let (_v1, expected_v2) = derive_api_base_urls(crate::config::Config::default_api_url_value());
    assert_eq!(client.base_url(), expected_v2);
}

#[tokio::test]
async fn test_reqwest_rejects_newline_authorization_header_as_builder_error() {
    super::ensure_crypto_provider();
    let request = Client::new()
        .get("https://example.com")
        .header("Authorization", "Bearer test-token\n");
    let error = request
        .send()
        .await
        .expect_err("newline header should fail before send");

    assert!(error.is_builder(), "expected builder error, got: {error}");
}

#[test]
fn test_new_with_token_override_trims_whitespace() {
    let _guard = test_env::lock();

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());
    test_env::remove_var("BORINGCACHE_API_TOKEN");

    let client = ApiClient::new_with_token_override(Some("  test-token\n".to_string()))
        .expect("client should initialize");
    assert_eq!(client.get_token().unwrap(), "test-token");

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
}

#[tokio::test]
async fn test_authenticated_builder_errors_do_not_retry() {
    super::ensure_crypto_provider();
    let client = ApiClient {
        client: Client::new(),
        transfer_client: Client::new(),
        base_url: "https://api.example.com/v2".to_string(),
        v1_base_url: "https://api.example.com/v1".to_string(),
        v2_base_url: "https://api.example.com/v2".to_string(),
        auth_token: Some("test-token\n".to_string()),
        capabilities: Arc::new(RwLock::new(None)),
    };

    let (result, retry_count) = client
        .send_authenticated_request_with_retry_count(client.get_client().get("https://example.com"))
        .await;

    let error = result.expect_err("invalid token header should fail");
    let message = error.to_string();
    assert_eq!(retry_count, 0);
    assert!(
        message.contains("Invalid API request before send"),
        "unexpected error message: {message}"
    );
    assert!(!message.contains("after 3 attempts"));
}

#[tokio::test]
async fn test_public_builder_errors_do_not_retry() {
    super::ensure_crypto_provider();
    let client = ApiClient {
        client: Client::new(),
        transfer_client: Client::new(),
        base_url: "https://api.example.com/v2".to_string(),
        v1_base_url: "https://api.example.com/v1".to_string(),
        v2_base_url: "https://api.example.com/v2".to_string(),
        auth_token: None,
        capabilities: Arc::new(RwLock::new(None)),
    };

    let error = client
        .send_public_request(
            client
                .get_client()
                .get("https://example.com")
                .header("Authorization", "Bearer test-token\n"),
        )
        .await
        .expect_err("invalid header should fail");
    let message = error.to_string();
    assert!(
        message.contains("Invalid API request before send"),
        "unexpected error message: {message}"
    );
    assert!(!message.contains("after 3 attempts"));
}

#[test]
fn test_parse_error_payload_with_details() {
    let body = r#"{
        "success": false,
        "error": "Validation failed",
        "details": ["Tag is invalid", "Path is missing"],
        "code": "invalid_tag"
    }"#;

    let parsed = parse_error_payload(body).expect("payload should parse");
    assert_eq!(parsed.message, "Validation failed");
    assert_eq!(parsed.success, Some(false));
    assert_eq!(parsed.code.as_deref(), Some("invalid_tag"));
    assert_eq!(parsed.details.len(), 2);
    assert_eq!(parsed.details[0], "Tag is invalid");
}

#[test]
fn test_format_error_message_includes_details() {
    let body = r#"{
        "success": false,
        "error": "Validation failed",
        "details": ["Tag is invalid"],
        "code": "invalid_tag"
    }"#;

    let payload = parse_error_payload(body).expect("payload should parse");
    let url = reqwest::Url::parse("https://api.boringcache.com/v1/test").unwrap();
    let message =
        format_error_message(StatusCode::UNPROCESSABLE_ENTITY, &url, Some(&payload), body);

    assert!(message.contains("422"));
    assert!(message.contains("Validation failed"));
    assert!(message.contains("invalid_tag"));
    assert!(message.contains("Tag is invalid"));
}

#[test]
fn test_format_error_message_fallback() {
    let url = reqwest::Url::parse("https://api.boringcache.com/v1/test").unwrap();
    let message = format_error_message(StatusCode::BAD_REQUEST, &url, None, "plain error body");
    assert!(message.contains("plain error body"));
}

#[test]
fn test_parse_conflict_metadata_prefers_current_pointer() {
    let body = r#"{
        "message": "publish conflict",
        "current_pointer": {
            "version": "42",
            "cache_entry_id": "entry-xyz",
            "tag": "main-tag"
        }
    }"#;

    let metadata = parse_conflict_metadata(body).expect("metadata should parse");
    assert_eq!(metadata.current_version.as_deref(), Some("42"));
    assert_eq!(
        metadata.current_cache_entry_id.as_deref(),
        Some("entry-xyz")
    );
    assert_eq!(metadata.current_tag.as_deref(), Some("main-tag"));
}

#[test]
fn test_parse_conflict_metadata_returns_none_for_unrecognized_payload() {
    let body = r#"{
        "message": "publish conflict",
        "status": "conflict",
        "details": ["retry later"]
    }"#;

    assert!(parse_conflict_metadata(body).is_none());
}

#[test]
fn test_should_retry_confirm_publish_error_detects_transient_statuses() {
    let internal = anyhow::anyhow!("confirm failed: Server error (500). Please try again later.");
    assert!(should_retry_confirm_publish_error(&internal));

    let throttled =
        anyhow::anyhow!("Rate limit exceeded (429 Too Many Requests). Please try again later.");
    assert!(should_retry_confirm_publish_error(&throttled));

    let permanent = anyhow::anyhow!("Server returned 403 Forbidden");
    assert!(!should_retry_confirm_publish_error(&permanent));
}

#[test]
fn test_confirm_publish_error_delay_backs_off_from_base_interval() {
    let internal = anyhow::anyhow!("confirm failed: Server error (500)");
    assert_eq!(
        confirm_publish_error_delay(&internal, 1),
        Duration::from_secs(1)
    );
    let throttled = anyhow::anyhow!("429 Too Many Requests");
    assert_eq!(
        confirm_publish_error_delay(&throttled, 1),
        Duration::from_secs(2)
    );
}

#[test]
fn test_retryable_api_status_includes_transient_server_errors() {
    assert!(is_retryable_api_status(StatusCode::REQUEST_TIMEOUT));
    assert!(is_retryable_api_status(StatusCode::TOO_MANY_REQUESTS));
    assert!(is_retryable_api_status(StatusCode::INTERNAL_SERVER_ERROR));
    assert!(is_retryable_api_status(StatusCode::BAD_GATEWAY));
    assert!(is_retryable_api_status(StatusCode::SERVICE_UNAVAILABLE));
    assert!(is_retryable_api_status(StatusCode::GATEWAY_TIMEOUT));
    assert!(!is_retryable_api_status(StatusCode::FORBIDDEN));
}

#[test]
fn test_confirm_publish_request_timeout_uses_default_and_env_override() {
    let _guard = test_env::lock();
    test_env::remove_var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV);
    assert_eq!(
        confirm_publish_request_timeout(),
        Duration::from_secs(DEFAULT_CONFIRM_PUBLISH_TIMEOUT_SECS)
    );

    test_env::set_var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV, "7");
    assert_eq!(confirm_publish_request_timeout(), Duration::from_secs(7));

    test_env::remove_var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV);
}

#[test]
fn test_transfer_connect_timeout_uses_default_and_env_override() {
    let _guard = test_env::lock();
    test_env::remove_var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV);
    assert_eq!(
        transfer_connect_timeout(),
        Duration::from_secs(DEFAULT_TRANSFER_CONNECT_TIMEOUT_SECS)
    );

    test_env::set_var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV, "15");
    assert_eq!(transfer_connect_timeout(), Duration::from_secs(15));

    test_env::remove_var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV);
}

#[test]
fn test_determine_publish_mode_prefers_explicit_storage_mode() {
    let request = cache::ConfirmRequest {
        manifest_digest: "sha256:abc".to_string(),
        manifest_size: 1,
        manifest_etag: None,
        archive_size: Some(1),
        archive_etag: None,
        blob_count: Some(5),
        blob_total_size_bytes: Some(100),
        file_count: None,
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("archive".to_string()),
        tag: None,
        write_scope_tag: None,
    };

    assert_eq!(determine_publish_mode(&request), "replace");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_manifest_check_request_body() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!("skipping test_manifest_check_request_body: networking disabled in sandbox");
        return;
    }

    // Isolate from user config
    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/check")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .match_body(Matcher::PartialJson(json!({
            "manifest_checks": [
                {
                    "tag": "abc123def456",
                    "manifest_root_digest": "blake3:abc"
                }
            ]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"results":[{"tag":"abc123def456","exists":true,"manifest_root_digest":"blake3:abc"}]}"#)
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let response = client
        .check_manifests(
            "ns/ws",
            &[cache::ManifestCheckRequest {
                tag: "abc123def456".to_string(),
                manifest_root_digest: "blake3:abc".to_string(),
                lookup: None,
            }],
        )
        .await
        .expect("manifest check should succeed");

    assert_eq!(response.results.len(), 1);
    let result = &response.results[0];
    assert!(result.exists);
    assert_eq!(result.tag, "abc123def456");

    mock.assert_async().await;

    // Cleanup: restore HOME and remove API URL override
    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_blob_check_request_body() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!("skipping test_blob_check_request_body: networking disabled in sandbox");
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [
                {
                    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "size_bytes": 1234
                }
            ]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"results":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","exists":true}]}"#)
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let response = client
        .check_blobs(
            "ns/ws",
            &[cache::BlobDescriptor {
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size_bytes: 1234,
            }],
            true,
        )
        .await
        .expect("blob check should succeed");

    assert_eq!(response.results.len(), 1);
    assert!(response.results[0].exists);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_blob_check_batches_large_requests() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_blob_check_batches_large_requests: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .expect(2)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"results":[{"digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","exists":true}]}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let blobs = (0..(BLOB_CHECK_BATCH_MAX + 1))
        .map(|index| cache::BlobDescriptor {
            digest: digest_for(index),
            size_bytes: 1,
        })
        .collect::<Vec<_>>();

    let response = client
        .check_blobs("ns/ws", &blobs, false)
        .await
        .expect("blob check should succeed");
    assert_eq!(response.results.len(), 2);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_blob_upload_urls_batches_large_requests() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_blob_upload_urls_batches_large_requests: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/stage")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .expect(2)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"upload_urls":[{"digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","url":"https://example.com/upload","headers":{}}],"already_present":[]}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let blobs = (0..(BLOB_URL_BATCH_MAX + 1))
        .map(|index| cache::BlobDescriptor {
            digest: digest_for(index),
            size_bytes: 1,
        })
        .collect::<Vec<_>>();

    let response = client
        .blob_upload_urls("ns/ws", "entry-1", &blobs)
        .await
        .expect("blob upload urls should succeed");
    assert_eq!(response.upload_urls.len(), 2);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_blob_upload_urls_sends_cache_entry_id() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_blob_upload_urls_sends_cache_entry_id: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/stage")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .match_body(mockito::Matcher::PartialJsonString(
            r#"{"cache_entry_id":"test-entry-42"}"#.to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"upload_urls":[],"already_present":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let blobs = vec![cache::BlobDescriptor {
        digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        size_bytes: 100,
    }];

    let response = client
        .blob_upload_urls("ns/ws", "test-entry-42", &blobs)
        .await
        .expect("blob upload urls should succeed");
    assert_eq!(response.already_present.len(), 1);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_blob_download_urls_batches_large_requests() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_blob_download_urls_batches_large_requests: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/download-urls")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .expect(2)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"download_urls":[{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","url":"https://example.com/download"}],"missing":[]}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let blobs = (0..(BLOB_URL_BATCH_MAX + 1))
        .map(|index| cache::BlobDescriptor {
            digest: digest_for(index),
            size_bytes: 1,
        })
        .collect::<Vec<_>>();

    let response = client
        .blob_download_urls("ns/ws", "entry-1", &blobs, false)
        .await
        .expect("blob download urls should succeed");
    assert_eq!(response.download_urls.len(), 2);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_blob_download_urls_can_verify_storage() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_blob_download_urls_can_verify_storage: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/download-urls")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-verify",
            "verify_storage": true,
            "blobs": [{
                "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "size_bytes": 42
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"download_urls":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","url":"https://example.com/download"}],"missing":[]}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let blobs = vec![cache::BlobDescriptor {
        digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        size_bytes: 42,
    }];

    let response = client
        .blob_download_urls("ns/ws", "entry-verify", &blobs, true)
        .await
        .expect("blob download urls should succeed");
    assert_eq!(response.download_urls.len(), 1);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_cache_inspect_request() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!("skipping test_cache_inspect_request: networking disabled in sandbox");
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/v2/workspaces/ns/ws/caches/inspect/ruby-deps")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"workspace":{"name":"Rails","slug":"ns/ws"},"identifier":{"query":"ruby-deps","matched_by":"tag"},"entry":{"id":"entry-1","primary_tag":"ruby-deps","status":"ready","manifest_root_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest_format_version":1,"storage_mode":"archive","stored_size_bytes":1024,"uncompressed_size":4096,"compressed_size":1024,"archive_size":1024,"file_count":32,"compression_algorithm":"zstd","blob_count":null,"blob_total_size_bytes":null,"cas_layout":null,"storage_verified":false,"hit_count":7,"created_at":"2026-03-31T12:00:00Z","uploaded_at":"2026-03-31T12:01:00Z","last_accessed_at":"2026-03-31T12:02:00Z","expires_at":null,"encrypted":false,"encryption_algorithm":null,"encryption_recipient_hint":null,"server_signed":false,"server_signed_at":null},"tags":[{"name":"ruby-deps","primary":true,"system":false,"created_at":"2026-03-31T12:00:00Z","updated_at":"2026-03-31T12:00:00Z"}],"versions":{"tag":"ruby-deps","version_count":1,"max_versions":10,"current":true,"total_storage_bytes":1024},"performance":{"total_operations":1,"saves":0,"restores":1,"avg_restore_ms":120.0,"avg_save_ms":0.0,"errors":0,"avg_download_speed":0.0,"avg_upload_speed":0.0,"last_operation":"2026-03-31T12:02:00Z","error_rate":0.0}}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
        .expect("client should initialize");

    let response = client
        .inspect_cache("ns/ws", "ruby-deps")
        .await
        .expect("cache inspect should succeed")
        .expect("cache inspect should return a payload");

    assert_eq!(response.workspace.slug, "ns/ws");
    assert_eq!(response.identifier.matched_by, "tag");
    assert_eq!(response.entry.id, "entry-1");
    assert_eq!(response.tags.len(), 1);

    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_create_cli_connect_session_without_auth_token() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_create_cli_connect_session_without_auth_token: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());
    test_env::remove_var("BORINGCACHE_API_TOKEN");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/cli-connect/sessions")
        .match_header("content-type", "application/json")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"session_id":"abc123","poll_token":"poll-secret","user_code":"ABCD-EF12","verification_url":"https://boringcache.com/cli/connect","authorize_url":"https://boringcache.com/cli/connect/abc123","expires_at":"2026-03-02T12:00:00Z","poll_interval_seconds":3}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new().expect("client should initialize without auth token");
    let response = client
        .create_cli_connect_session()
        .await
        .expect("cli connect session should be created");

    assert_eq!(response.session_id, "abc123");
    assert_eq!(response.poll_token, "poll-secret");
    assert_eq!(response.user_code, "ABCD-EF12");
    assert_eq!(
        response.verification_url,
        "https://boringcache.com/cli/connect"
    );
    assert_eq!(response.poll_interval_seconds, 3);
    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_poll_cli_connect_session_rejects_invalid_poll_token() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_poll_cli_connect_session_rejects_invalid_poll_token: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());
    test_env::remove_var("BORINGCACHE_API_TOKEN");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/v2/cli-connect/sessions/abc123")
        .match_header("x-boringcache-connect-token", "invalid-token")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"Invalid poll token"}"#)
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new().expect("client should initialize without auth token");
    let error = client
        .poll_cli_connect_session("abc123", "invalid-token")
        .await
        .expect_err("polling with invalid token should fail");
    let message = error.to_string();
    assert!(
        message.contains("CLI connect poll rejected"),
        "unexpected error message: {message}"
    );
    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_start_cli_connect_email_auth_without_auth_token() {
    let _guard = test_env::lock();

    if !networking_available() {
        eprintln!(
            "skipping test_start_cli_connect_email_auth_without_auth_token: networking disabled in sandbox"
        );
        return;
    }

    let temp_home = tempfile::tempdir().expect("failed to create temp dir");
    let original_home = std::env::var("HOME").ok();
    test_env::set_var("HOME", temp_home.path());
    test_env::remove_var("BORINGCACHE_API_TOKEN");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v2/cli-connect/sessions/abc123/email-auth")
        .match_header("content-type", "application/json")
        .match_body(
            Matcher::Json(json!({
                "email": "new@example.com",
                "name": "New User",
                "username": "new-user"
            })),
        )
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"session_id":"abc123","status":"email_sent","next_step":"Check your email to continue, then return to approve CLI access.","field_errors":{}}"#,
        )
        .create_async()
        .await;

    test_env::set_var("BORINGCACHE_API_URL", server.url());

    let client = ApiClient::new().expect("client should initialize without auth token");
    let response = client
        .start_cli_connect_email_auth(
            "abc123",
            &crate::api::models::cli_connect::CliConnectEmailAuthRequest {
                email: "new@example.com".to_string(),
                name: Some("New User".to_string()),
                username: Some("new-user".to_string()),
            },
        )
        .await
        .expect("cli connect email auth should succeed");

    assert_eq!(response.session_id, "abc123");
    assert_eq!(response.status, "email_sent");
    mock.assert_async().await;

    if let Some(home) = original_home {
        test_env::set_var("HOME", home);
    }
    test_env::remove_var("BORINGCACHE_API_URL");
}

#[test]
fn test_map_restore_result_prefers_top_level_cas_fields() {
    let mapped = ApiClient::map_restore_result(cache::RestoreResult {
        tag: "cas-tag".to_string(),
        primary_tag: Some("cas-tag-root".to_string()),
        signature_tag: Some("cas-signature-tag".to_string()),
        status: "hit".to_string(),
        cache_entry_id: Some("entry-1".to_string()),
        manifest_root_digest: Some(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        ),
        manifest_digest: None,
        manifest_url: Some("https://example.test/manifest".to_string()),
        compression_algorithm: Some("zstd".to_string()),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(9),
        blob_total_size_bytes: Some(4096),
        cas_layout: Some("oci-v1".to_string()),
        archive_urls: vec![],
        metadata: Some(cache::RestoreMetadata {
            manifest_root_digest: None,
            total_size_bytes: Some(99),
            storage_mode: Some("archive".to_string()),
            blob_count: Some(1),
            blob_total_size_bytes: Some(1),
            cas_layout: Some("file-v1".to_string()),
            uncompressed_size: None,
            compressed_size: None,
            file_count: None,
            compression_algorithm: None,
            signature_tag: Some("ignored-metadata-tag".to_string()),
        }),
        error: None,
        pending: false,
        workspace_signing_public_key: None,
        workspace_signing_key_fingerprint: None,
        server_signature: None,
        server_signature_payload: None,
        server_envelope_signature: None,
        server_signature_version: None,
        server_signing_key_id: None,
        server_signed_at: None,
        encrypted: false,
    });

    assert_eq!(mapped.primary_tag.as_deref(), Some("cas-tag-root"));
    assert_eq!(mapped.signature_tag.as_deref(), Some("cas-signature-tag"));
    assert_eq!(mapped.storage_mode.as_deref(), Some("cas"));
    assert_eq!(mapped.blob_count, Some(9));
    assert_eq!(mapped.blob_total_size_bytes, Some(4096));
    assert_eq!(mapped.cas_layout.as_deref(), Some("oci-v1"));
}

#[test]
fn test_map_restore_result_uses_metadata_cas_fields_as_fallback() {
    let mapped = ApiClient::map_restore_result(cache::RestoreResult {
        tag: "cas-tag".to_string(),
        primary_tag: None,
        signature_tag: None,
        status: "hit".to_string(),
        cache_entry_id: Some("entry-2".to_string()),
        manifest_root_digest: None,
        manifest_digest: None,
        manifest_url: Some("https://example.test/manifest".to_string()),
        compression_algorithm: Some("zstd".to_string()),
        storage_mode: None,
        blob_count: None,
        blob_total_size_bytes: None,
        cas_layout: None,
        archive_urls: vec![],
        metadata: Some(cache::RestoreMetadata {
            manifest_root_digest: Some(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            ),
            total_size_bytes: Some(100),
            storage_mode: Some("cas".to_string()),
            blob_count: Some(3),
            blob_total_size_bytes: Some(2048),
            cas_layout: Some("bazel-v2".to_string()),
            uncompressed_size: None,
            compressed_size: None,
            file_count: None,
            compression_algorithm: None,
            signature_tag: Some("metadata-signature-tag".to_string()),
        }),
        error: None,
        pending: false,
        workspace_signing_public_key: None,
        workspace_signing_key_fingerprint: None,
        server_signature: None,
        server_signature_payload: None,
        server_envelope_signature: None,
        server_signature_version: None,
        server_signing_key_id: None,
        server_signed_at: None,
        encrypted: false,
    });

    assert_eq!(mapped.storage_mode.as_deref(), Some("cas"));
    assert_eq!(
        mapped.signature_tag.as_deref(),
        Some("metadata-signature-tag")
    );
    assert_eq!(mapped.blob_count, Some(3));
    assert_eq!(mapped.blob_total_size_bytes, Some(2048));
    assert_eq!(mapped.cas_layout.as_deref(), Some("bazel-v2"));
}

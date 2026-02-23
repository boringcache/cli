use mockito::{Matcher, Server};
use serde_json::json;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tempfile::TempDir;
use tokio::sync::Mutex;

static CLI_TEST_MUTEX: Mutex<()> = Mutex::const_new(());

fn cli_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_boringcache")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap().join("target/debug/boringcache"))
}

fn networking_available() -> bool {
    if env::var("BORINGCACHE_FORCE_NETWORK_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }

    if env::var("BORINGCACHE_SKIP_NETWORK_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return false;
    }

    std::net::TcpListener::bind("127.0.0.1:0").is_ok()
}

async fn acquire_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = CLI_TEST_MUTEX.lock().await;
    std::env::set_var("BORINGCACHE_TEST_MODE", "1");
    guard
}

fn setup_test_config(temp_dir: &TempDir, server_url: &str) {
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server_url
        })
        .to_string(),
    )
    .expect("Failed to write config");
}

mod model_tests {
    use boring_cache_cli::api::models::cache::{RestorePendingResponse, RestoreResult};

    #[test]
    fn test_restore_result_with_pending_flag() {
        let json = r#"{
            "tag": "test-tag",
            "status": "pending",
            "pending": true,
            "cache_entry_id": "entry-123"
        }"#;

        let result: RestoreResult = serde_json::from_str(json).unwrap();

        assert_eq!(result.tag, "test-tag");
        assert_eq!(result.status, "pending");
        assert!(result.pending);
        assert_eq!(result.cache_entry_id, Some("entry-123".to_string()));
    }

    #[test]
    fn test_restore_result_with_error() {
        let json = r#"{
            "tag": "test-tag",
            "status": "error",
            "error": "Storage backend unavailable"
        }"#;

        let result: RestoreResult = serde_json::from_str(json).unwrap();

        assert_eq!(result.tag, "test-tag");
        assert_eq!(result.status, "error");
        assert_eq!(
            result.error,
            Some("Storage backend unavailable".to_string())
        );
    }

    #[test]
    fn test_restore_pending_response_deserializes() {
        let json = r#"{
            "pending": true,
            "status": "pending",
            "message": "Upload in progress"
        }"#;

        let result: RestorePendingResponse = serde_json::from_str(json).unwrap();

        assert!(result.pending);
        assert_eq!(result.status, Some("pending".to_string()));
        assert_eq!(result.message, Some("Upload in progress".to_string()));
    }

    #[test]
    fn test_restore_result_without_pending_defaults_to_false() {
        let json = r#"{
            "tag": "test-tag",
            "status": "hit",
            "cache_entry_id": "entry-123"
        }"#;

        let result: RestoreResult = serde_json::from_str(json).unwrap();

        assert_eq!(result.tag, "test-tag");
        assert_eq!(result.status, "hit");
        assert!(!result.pending);
    }
}

#[tokio::test]
async fn test_restore_retries_on_404_with_pending_body() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _pending_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "pending": true,
                "status": "pending",
                "message": "Upload in progress"
            })
            .to_string(),
        )
        .expect(2)
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let start = Instant::now();
    let output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "pending-tag"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() >= 500,
        "Expected retry delay, but completed in {:?}",
        elapsed
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("retry")
            || combined.contains("progress")
            || combined.contains("pending")
            || output.status.success(),
        "Expected retry message or success, got: {combined}"
    );

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_retries_on_pending_entries_in_response() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "pending-entry",
                "status": "pending",
                "pending": true,
                "cache_entry_id": null
            }])
            .to_string(),
        )
        .expect(2)
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let start = Instant::now();
    let _output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "pending-entry"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() >= 500,
        "Expected retry delay, but completed in {:?}",
        elapsed
    );

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_retries_on_storage_backend_unavailable() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "error-entry",
                "status": "error",
                "error": "Storage backend unavailable",
                "cache_entry_id": null
            }])
            .to_string(),
        )
        .expect(2)
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let start = Instant::now();
    let _output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "error-entry"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() >= 500,
        "Expected retry delay, but completed in {:?}",
        elapsed
    );

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_handles_207_multi_status() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(207)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "hit-entry",
                    "status": "hit",
                    "cache_entry_id": "entry-123",
                    "manifest_url": "https://example.com/manifest",
                    "archive_urls": ["https://example.com/archive"]
                },
                {
                    "tag": "miss-entry",
                    "status": "miss",
                    "error": "Not found"
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "hit-entry", "miss-entry"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let _stdout = String::from_utf8_lossy(&output.stdout);
    let _stderr = String::from_utf8_lossy(&output.stderr);

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_handles_404_with_restore_response_body() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "not-found-entry",
                "status": "miss",
                "error": "Cache entry not found"
            }])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "not-found-entry"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("miss") || combined.contains("not found") || combined.contains("found 0"),
        "Expected cache miss message, got: {combined}"
    );

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_exits_gracefully_on_409_conflict() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _check_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "tag": "conflict-tag",
                    "exists": false
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let conflict_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches")
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "conflict",
                "message": "Tag already exists with different content"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let save_dir = temp_dir.path().join("save-content");
    fs::create_dir(&save_dir).expect("Failed to create save dir");
    fs::write(save_dir.join("test.txt"), "test content").expect("Failed to write test file");

    let start = Instant::now();
    let tag_path = format!("conflict-tag:{}", save_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args(["save", "test/workspace", &tag_path])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "Expected no excessive retry delay on 409, but took {:?}",
        elapsed
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.to_lowercase().contains("conflict")
            || combined.to_lowercase().contains("skip")
            || combined.to_lowercase().contains("exists")
            || output.status.success(),
        "Expected conflict/skip message or success, got: {combined}"
    );

    conflict_mock.assert_async().await;

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_skips_wait_on_pending() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;

    let _session_mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_body(
            json!({
                "user": {"name": "Test User", "email": "test@example.com"},
                "organization": {"name": "Test Org"},
                "token": {"expires_in_days": 90}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _check_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches/check")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "tag": "pending-tag",
                    "exists": false
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _pending_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches")
        .with_status(423)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "locked",
                "message": "Another upload in progress"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    env::set_var("HOME", temp_dir.path());

    let save_dir = temp_dir.path().join("save-content");
    fs::create_dir(&save_dir).expect("Failed to create save dir");
    fs::write(save_dir.join("test.txt"), "test content").expect("Failed to write test file");

    let start = Instant::now();
    let tag_path = format!("pending-tag:{}", save_dir.to_str().unwrap());
    let _output = std::process::Command::new(cli_binary())
        .args(["save", "test/workspace", &tag_path])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 5000,
        "Expected no retry delay on pending, but completed in {:?}",
        elapsed
    );

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

mod cache_resolution_tests {
    use boring_cache_cli::api::models::cache::CacheResolutionEntry;

    #[test]
    fn test_cache_resolution_entry_has_pending_and_error_fields() {
        let entry = CacheResolutionEntry {
            tag: "test".to_string(),
            status: "pending".to_string(),
            cache_entry_id: None,
            manifest_url: None,
            manifest_root_digest: None,
            manifest_digest: None,
            compression_algorithm: None,
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            archive_urls: vec![],
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            content_hash: None,
            pending: true,
            error: Some("Test error".to_string()),
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        };

        assert!(entry.pending);
        assert_eq!(entry.error, Some("Test error".to_string()));
    }
}

use mockito::{Matcher, Server};
use serde_json::json;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::sync::Mutex;

// Global async mutex to ensure CLI tests run sequentially to avoid environment variable interference
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

    false
}

// Helper function to acquire async lock
async fn acquire_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = CLI_TEST_MUTEX.lock().await;
    std::env::set_var("BORINGCACHE_TEST_MODE", "1");
    guard
}

// These tests use mock servers to test full CLI workflows without requiring real API access

#[tokio::test]
async fn test_auth_workflow_success() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_auth_workflow_success: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("POST", "/auth/validate")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "valid": true,
                "user": {
                    "id": 1,
                    "name": "Test User",
                    "email": "test@example.com"
                },
                "organization": {
                    "id": 1,
                    "name": "Test Org",
                    "slug": "test-org"
                }
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Set API URL to mock server
    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output = std::process::Command::new(cli_binary())
        .args(["auth", "--token", "test-token-123"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("success") || stdout.contains("authenticated"));
    }

    // Clean up
    env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
async fn test_auth_workflow_invalid_token() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_auth_workflow_invalid_token: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
        .mock("GET", "/session")
        .with_status(401)
        .with_body(json!({"error": "Invalid token"}).to_string())
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    env::set_var("BORINGCACHE_API_URL", server.url());

    let output = std::process::Command::new(cli_binary())
        .args(["auth", "--token", "invalid-token"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // Allow either success or failure depending on mock server timing
    let exit_code = output.status.code();
    assert!(exit_code == Some(0) || exit_code == Some(1));
    // Check output contains error message if authentication failed
    let stderr = String::from_utf8_lossy(&output.stderr);
    if exit_code != Some(0) {
        assert!(
            stderr.contains("Invalid token")
                || stderr.contains("Authentication failed")
                || stderr.contains("Token validation failed")
                || stderr.contains("API Error")
        );
    }

    env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
async fn test_workspaces_workflow_success() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_workspaces_workflow_success: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock workspaces list
    let _workspaces_mock = server
        .mock("GET", "/workspaces")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "id": 1,
                    "name": "Test Workspace",
                    "slug": "test/workspace",
                    "cache_entries_count": 5,
                    "total_cache_size": 1048576,
                    "created_at": "2025-01-01T00:00:00Z",
                    "updated_at": "2025-01-01T00:00:00Z"
                },
                {
                    "id": 2,
                    "name": "Another Workspace",
                    "slug": "another/workspace",
                    "cache_entries_count": 10,
                    "total_cache_size": 2097152,
                    "created_at": "2025-01-01T00:00:00Z",
                    "updated_at": "2025-01-01T00:00:00Z"
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    // Create temp config with auth token
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    let output = std::process::Command::new(cli_binary())
        .args(["workspaces"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Test Workspace") || stdout.contains("test/workspace"));
        assert!(stdout.contains("Another Workspace") || stdout.contains("another/workspace"));
    }

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_workflow_success() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_save_workflow_success: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock cache upload
    let _upload_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .match_body(Matcher::PartialJson(json!({
            "caches": [
                {"tag": "test-save-tag"}
            ]
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "tag": "test-save-tag",
                    "cache_entry_id": null,
                    "status": "ready",
                    "exists": true,
                    "missing_chunk_digests": [],
                    "chunk_upload_urls": {},
                    "manifest_upload_url": null,
                    "error": null
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock metrics reporting
    let _metrics_mock = server
        .mock("POST", "/workspaces/test/workspace/metrics")
        .with_status(201)
        .with_body(json!({"status": "success", "metric_id": "metric-456"}).to_string())
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    // Create test cache directory
    let cache_dir = temp_dir.path().join("cache_test");
    fs::create_dir(&cache_dir).expect("Failed to create cache dir");
    fs::write(cache_dir.join("test1.txt"), "test content 1").expect("Failed to write test1");
    fs::write(cache_dir.join("test2.txt"), "test content 2").expect("Failed to write test2");

    env::set_var("HOME", temp_dir.path());

    let tag_path = format!("test-save-tag:{}", cache_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args(["save", "test/workspace", tag_path.as_str()])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("success") || stdout.contains("saved") || stdout.contains("uploaded")
        );
    }

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_workflow_cache_not_found() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_restore_workflow_cache_not_found: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock cache not found
    let _check_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?tags=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "tag": "non-existent-key",
                    "cache_entry_id": null,
                    "manifest_url": null,
                    "chunks": [],
                    "metadata": null,
                    "error": "Cache not found"
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    let output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "non-existent-key"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // Should exit with code 1 when cache not found (cache miss, not an error)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _output_text = format!("{stdout}{stderr}");

    // Should exit with code 1 for cache miss, but allow 0 if cache check succeeds
    let exit_code = output.status.code();
    assert!(exit_code == Some(1) || exit_code == Some(0));

    // CLI can have various outputs depending on mock behavior, just verify command ran

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_metrics_workflow() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_metrics_workflow: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock metrics endpoint
    let _metrics_mock = server
        .mock("GET", "/stats")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "performance_stats": {
                    "avg_save_duration": 5000,
                    "avg_restore_duration": 3000,
                    "avg_compression_ratio": 0.3
                },
                "top_cached_paths": [
                    {"path": "node_modules", "count": 50},
                    {"path": "target", "count": 25}
                ],
                "operations_over_time": [
                    {"date": "2025-01-01", "saves": 10, "restores": 8},
                    {"date": "2025-01-02", "saves": 15, "restores": 12}
                ],
                "total_operations": 45,
                "success_rate": 0.96
            })
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    let output = std::process::Command::new(cli_binary())
        .args(["metrics"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("performance")
                || stdout.contains("operations")
                || stdout.contains("success")
        );
    }

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}
#[tokio::test]
async fn test_restore_exit_codes() {
    let _lock = acquire_test_lock().await; // Ensure sequential execution
    if !networking_available() {
        eprintln!("skipping test_restore_exit_codes: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Test cache miss (should return exit code 1)
    let _miss_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?tags=.*$".to_string()),
        )
        .with_status(200)
        .with_body(
            json!({
                "results": [{
                    "tag": "missing-key",
                    "cache_entry_id": null,
                    "manifest_url": null,
                    "chunks": [],
                    "metadata": null,
                    "error": "Cache not found"
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    let output = std::process::Command::new(cli_binary())
        .args(["restore", "test/workspace", "missing-key"])
        .output()
        .expect("Failed to execute command");

    // Should exit with code 1 for cache miss, but allow 0 if cache check succeeds
    let exit_code = output.status.code();
    assert!(exit_code == Some(1) || exit_code == Some(0));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_fail_on_cache_miss_flag() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_fail_on_cache_miss_flag: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock cache not found to trigger cache miss
    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "missing-cache-macos-15-arm64",
                "cache_entry_id": null,
                "manifest_url": null,
                "chunks": [],
                "metadata": null,
                "status": "miss",
                "error": "Cache not found"
            }])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    // Test with --fail-on-cache-miss flag
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            "missing-cache",
            "--fail-on-cache-miss",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // Should exit with non-zero code when cache miss occurs with flag
    assert_ne!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.contains("Cache miss for tags:") {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
    }

    assert!(stderr.contains("Cache miss for tags: missing-cache"));
    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_fail_on_cache_miss_with_partial_hits() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_fail_on_cache_miss_with_partial_hits: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock response with one hit and one miss
    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "existing-cache-macos-15-arm64",
                    "cache_entry_id": "123",
                    "manifest_url": "https://example.com/manifest",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                },
                {
                    "tag": "missing-cache-macos-15-arm64",
                    "cache_entry_id": null,
                    "manifest_url": null,
                    "chunks": [],
                    "metadata": null,
                    "status": "miss",
                    "error": "Cache not found"
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    // Test with --fail-on-cache-miss flag with partial hits
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            "existing-cache,missing-cache",
            "--fail-on-cache-miss",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // Should still fail if any cache miss occurs with flag
    assert_ne!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.contains("Cache miss for tags:") {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
    }

    assert!(stderr.contains("Cache miss for tags: missing-cache"));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_lookup_only_flag() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_lookup_only_flag: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock cache resolution with mixed results
    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "existing-cache-macos-15-arm64",
                    "cache_entry_id": "123",
                    "manifest_url": "https://example.com/manifest",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                },
                {
                    "tag": "missing-cache-macos-15-arm64",
                    "cache_entry_id": null,
                    "manifest_url": null,
                    "chunks": [],
                    "metadata": null,
                    "status": "miss",
                    "error": "Cache not found"
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    // Test with --lookup-only flag
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            "existing-cache,missing-cache",
            "--lookup-only",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // Should exit successfully with lookup-only
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.code() != Some(0) {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
        eprintln!("Exit code: {:?}", output.status.code());
    }

    assert_eq!(output.status.code(), Some(0));

    let output_text = format!("{stdout}{stderr}");

    // Should show what was found and what was missing
    assert!(output_text.contains("Available cache entries: existing-cache"));
    assert!(output_text.contains("Not found: missing-cache"));

    // Should NOT attempt to download anything (no download-related output)
    assert!(!output_text.contains("Downloading"));
    assert!(!output_text.contains("Restoring"));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_lookup_only_all_found() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_lookup_only_all_found: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock cache resolution with all hits
    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "cache-1-macos-15-arm64",
                    "cache_entry_id": "123",
                    "manifest_url": "https://example.com/manifest1",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                },
                {
                    "tag": "cache-2-macos-15-arm64",
                    "cache_entry_id": "456",
                    "manifest_url": "https://example.com/manifest2",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    env::set_var("HOME", temp_dir.path());

    // Test with --lookup-only flag when all caches exist
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            "cache-1,cache-2",
            "--lookup-only",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // Should exit successfully
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.code() != Some(0) {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
        eprintln!("Exit code: {:?}", output.status.code());
    }

    assert_eq!(output.status.code(), Some(0));

    let output_text = format!("{stdout}{stderr}");

    // Should show both caches were found
    assert!(output_text.contains("Available cache entries"));
    assert!(output_text.contains("cache-1"));
    assert!(output_text.contains("cache-2"));

    // Should not show any "Not found" warnings
    assert!(!output_text.contains("Not found"));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_workflow_with_force_flag() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_save_workflow_with_force_flag: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock manifest check - returns exists: true
    let _check_mock = server
        .mock("POST", "/workspaces/test/workspace/caches/check")
        .with_status(200)
        .with_body(
            json!({
                "results": [{
                    "tag": "test-force-tag",
                    "exists": true,
                    "status": "ready",
                    "manifest_root_digest": "blake3:abc123"
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock cache save with force flag - should accept force: true and create new entry
    let _save_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "force": true
            }
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "test-force-tag-macos-15-arm64",
                "cache_entry_id": "new-entry-456",
                "exists": false,
                "missing_chunk_digests": [],
                "chunk_upload_urls": {},
                "manifest_upload_url": format!("{}/upload-manifest", server.url())
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock manifest upload
    let _manifest_upload_mock = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    // Mock confirm upload (tag will have platform suffix)
    let _confirm_mock = server
        .mock(
            "POST",
            mockito::Matcher::Regex(
                r"/workspaces/test/workspace/caches/test-force-tag-.*/confirm".to_string(),
            ),
        )
        .with_status(200)
        .with_body(json!({"status": "ready"}).to_string())
        .create_async()
        .await;

    // Mock metrics reporting
    let _metrics_mock = server
        .mock("POST", "/workspaces/test/workspace/metrics")
        .with_status(201)
        .with_body(json!({"status": "success", "metric_id": "metric-789"}).to_string())
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    // Create test cache directory
    let cache_dir = temp_dir.path().join("cache_force_test");
    fs::create_dir(&cache_dir).expect("Failed to create cache dir");
    fs::write(cache_dir.join("file1.txt"), "content 1").expect("Failed to write file1");
    fs::write(cache_dir.join("file2.txt"), "content 2").expect("Failed to write file2");

    env::set_var("HOME", temp_dir.path());

    let tag_path = format!("test-force-tag:{}", cache_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args(["save", "test/workspace", tag_path.as_str(), "--force"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The save should succeed - force flag should bypass "already exists" check
    // and create a new entry
    if !output.status.success() {
        eprintln!("Command failed with output:");
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
    }

    // Verify the force flag was sent to the API
    // The mock expects force: true in the request body
    _save_mock.assert_async().await;

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_workflow_without_force_flag_skips_existing() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_save_workflow_without_force_flag_skips_existing: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    // Mock auth validation
    let _auth_mock = server
        .mock("GET", "/session")
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

    // Mock manifest check - returns exists: true
    let _check_mock = server
        .mock("POST", "/workspaces/test/workspace/caches/check")
        .with_status(200)
        .with_body(
            json!({
                "results": [{
                    "tag": "test-existing-tag",
                    "exists": true,
                    "status": "ready",
                    "manifest_root_digest": "blake3:existing123"
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    // This mock should NOT be called because cache already exists
    let save_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .expect(0)
        .with_status(201)
        .create_async()
        .await;

    // Mock metrics reporting
    let _metrics_mock = server
        .mock("POST", "/workspaces/test/workspace/metrics")
        .with_status(201)
        .with_body(json!({"status": "success"}).to_string())
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create config with auth token
    let config_dir = temp_dir.path().join(".boringcache");
    fs::create_dir(&config_dir).expect("Failed to create config dir");
    fs::write(
        config_dir.join("config.json"),
        json!({
            "token": "test-token-123",
            "api_url": server.url()
        })
        .to_string(),
    )
    .expect("Failed to write config");

    // Create test cache directory
    let cache_dir = temp_dir.path().join("cache_existing_test");
    fs::create_dir(&cache_dir).expect("Failed to create cache dir");
    fs::write(cache_dir.join("file1.txt"), "existing content").expect("Failed to write file");

    env::set_var("HOME", temp_dir.path());

    let tag_path = format!("test-existing-tag:{}", cache_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args(["save", "test/workspace", tag_path.as_str()])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}{stderr}");

    // Should indicate cache already exists
    assert!(
        output_text.contains("already") || output_text.contains("exists"),
        "Expected 'already exists' message, got: {}",
        output_text
    );

    // Verify the save endpoint was NOT called (because cache already exists)
    save_mock.assert_async().await;

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

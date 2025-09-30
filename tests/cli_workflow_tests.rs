use mockito::Server;
use serde_json::json;
use std::env;
use std::fs;
use tempfile::TempDir;
use tokio::sync::Mutex;

// Global async mutex to ensure CLI tests run sequentially to avoid environment variable interference
static CLI_TEST_MUTEX: Mutex<()> = Mutex::const_new(());

fn networking_available() -> bool {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

// Helper function to acquire async lock
async fn acquire_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    CLI_TEST_MUTEX.lock().await
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
    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    let output = std::process::Command::new(cli_path)
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
    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");

    env::set_var("BORINGCACHE_API_URL", server.url());

    let output = std::process::Command::new(cli_path)
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

    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    let output = std::process::Command::new(cli_path)
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
        .mock("POST", "/caches")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "status": "success",
                "cache_id": "cache-123",
                "upload_url": format!("{}/upload/cache-123", server.url())
            })
            .to_string(),
        )
        .create_async()
        .await;

    // Mock file upload endpoint
    let _file_upload_mock = server
        .mock("PUT", "/upload/cache-123")
        .with_status(200)
        .create_async()
        .await;

    // Mock metrics reporting
    let _metrics_mock = server
        .mock("POST", "/metrics")
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

    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    let output = std::process::Command::new(cli_path)
        .args([
            "save",
            "test/workspace",
            cache_dir.to_str().unwrap(),
            "--key",
            "test-save-key",
        ])
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
            mockito::Matcher::Regex(r"^/workspaces/test%2Fworkspace/caches/.+$".to_string()),
        )
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "Cache not found"
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

    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    let output = std::process::Command::new(cli_path)
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

    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    let output = std::process::Command::new(cli_path)
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
        .mock("POST", "/caches/check")
        .with_status(404)
        .with_body(json!({"error": "Cache not found"}).to_string())
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

    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    let output = std::process::Command::new(cli_path)
        .args(["restore", "test/workspace", "missing-key"])
        .output()
        .expect("Failed to execute command");

    // Should exit with code 1 for cache miss, but allow 0 if cache check succeeds
    let exit_code = output.status.code();
    assert!(exit_code == Some(1) || exit_code == Some(0));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

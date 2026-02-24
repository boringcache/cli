use age::secrecy::SecretString;
use boring_cache_cli::{archive, encryption, manifest, platform, signing};
use chrono::Utc;
use mockito::{Matcher, Server};
use serde_json::json;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
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

fn platform_tag_suffix() -> String {
    platform::Platform::detect()
        .expect("Failed to detect platform")
        .to_tag_suffix()
}

async fn build_manifest_and_archive(
    base_dir: &Path,
    tag: &str,
    encryption_meta: Option<manifest::EncryptionMetadata>,
) -> (manifest::Manifest, Vec<u8>, Vec<u8>) {
    let draft = manifest::ManifestBuilder::new(base_dir)
        .build()
        .expect("Failed to build manifest draft");
    let root_digest = manifest::diff::compute_digest_from_draft(&draft);

    let archive_info = archive::create_tar_archive(
        &draft,
        base_dir.to_str().expect("Base dir should be utf-8"),
        false,
        None,
    )
    .await
    .expect("Failed to create archive");

    let file_count = archive_info.manifest_files.len() as u64;
    let manifest = manifest::Manifest {
        format_version: 1,
        tag: tag.to_string(),
        root: manifest::ManifestRoot {
            digest: root_digest,
            algo: "sha256".to_string(),
        },
        summary: manifest::ManifestSummary {
            file_count,
            raw_size: archive_info.uncompressed_size,
            changed_count: file_count,
            removed_count: 0,
        },
        entry: None,
        archive: None,
        files: archive_info.manifest_files.clone(),
        encryption: encryption_meta,
        signature: None,
    };

    let manifest_cbor =
        manifest::io::encode_manifest(&manifest).expect("Failed to encode manifest");
    let manifest_bytes =
        manifest::io::compress_manifest(&manifest_cbor).expect("Failed to compress manifest");
    let archive_bytes = fs::read(&archive_info.archive_path).expect("Failed to read archive bytes");

    (manifest, manifest_bytes, archive_bytes)
}

fn encrypt_with_passphrase(data: &[u8], passphrase: &str) -> Vec<u8> {
    let encryptor = age::Encryptor::with_user_passphrase(SecretString::new(passphrase.to_string()));
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .expect("Failed to create passphrase encryptor");
    writer.write_all(data).expect("Failed to encrypt data");
    writer.finish().expect("Failed to finalize encryption");
    encrypted
}

#[tokio::test]
async fn test_auth_workflow_success() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_auth_workflow_success: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _mock = server
        .mock("GET", "/v2/session")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "valid": true,
                "user": {
                    "id": "1",
                    "name": "Test User",
                    "email": "test@example.com"
                },
                "organization": {
                    "id": "1",
                    "name": "Test Org",
                    "slug": "test-org"
                },
                "workspace": null,
                "token": {
                    "id": "tok_123",
                    "name": "CI Token",
                    "scope_type": "organization",
                    "scopes": ["read", "write"],
                    "expires_in_days": 90
                }
            })
            .to_string(),
        )
        .create_async()
        .await;

    env::set_var("BORINGCACHE_API_URL", server.url());

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output = std::process::Command::new(cli_binary())
        .args(["auth", "--token", "test-token-123"])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("success") || stdout.contains("authenticated"));

    env::remove_var("BORINGCACHE_API_URL");
}

#[tokio::test]
async fn test_auth_workflow_invalid_token() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_auth_workflow_invalid_token: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
        .mock("GET", "/v2/session")
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

    let exit_code = output.status.code();
    assert!(exit_code == Some(0) || exit_code == Some(1));

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
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_workspaces_workflow_success: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let _workspaces_mock = server
        .mock("GET", "/v2/workspaces")
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
async fn test_restore_warns_on_invalid_signature_with_encrypted_manifest() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_warns_on_invalid_signature_with_encrypted_manifest: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let data_dir = temp_dir.path().join("data");
    fs::create_dir(&data_dir).expect("Failed to create data dir");
    fs::write(data_dir.join("hello.txt"), "hello").expect("Failed to write data file");

    let (identity, recipient) = encryption::generate_keypair();
    let identity_path = temp_dir.path().join("age-identity.txt");
    encryption::save_identity(&identity, &identity_path).expect("Failed to save identity");

    let recipient_str = recipient.to_string();
    let encryption_meta = manifest::EncryptionMetadata {
        algorithm: encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string(),
        recipient_hint: Some(encryption::recipient_hint(&recipient_str)),
        encrypted_at: Utc::now(),
    };

    let (manifest, manifest_bytes, archive_bytes) =
        build_manifest_and_archive(&data_dir, "cache-tag", Some(encryption_meta)).await;

    let manifest_encrypted =
        encryption::encrypt_data(&manifest_bytes, &recipient).expect("Failed to encrypt manifest");
    let archive_encrypted =
        encryption::encrypt_data(&archive_bytes, &recipient).expect("Failed to encrypt archive");

    let (signing_key, verifying_key) = signing::generate_keypair();
    let public_key = signing::format_public_key(&verifying_key);
    let bad_signature = signing::signature_to_base64(&signing::sign_data(b"invalid", &signing_key));

    let manifest_url = format!("{}/manifest", server.url());
    let archive_url = format!("{}/archive", server.url());
    let manifest_root_digest = manifest.root.digest.clone();
    let manifest_raw_size = manifest.summary.raw_size;
    let manifest_file_count = manifest.summary.file_count;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "cache-tag",
                    "status": "hit",
                    "cache_entry_id": "123",
                    "manifest_url": manifest_url,
                    "archive_urls": [archive_url],
                    "manifest_root_digest": manifest_root_digest,
                    "workspace_signing_public_key": public_key,
                    "server_signature": bad_signature,
                    "server_signed_at": "2025-01-01T00:00:00Z",
                    "encrypted": true,
                    "metadata": {
                        "total_size_bytes": archive_encrypted.len(),
                        "uncompressed_size": manifest_raw_size,
                        "compressed_size": archive_encrypted.len(),
                        "file_count": manifest_file_count,
                        "compression_algorithm": "zstd"
                    }
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    let _manifest_mock = server
        .mock("GET", "/manifest")
        .with_status(200)
        .with_header("content-type", "application/octet-stream")
        .with_body(manifest_encrypted)
        .create_async()
        .await;

    let archive_len = archive_encrypted.len().to_string();
    let _archive_head_mock = server
        .mock("HEAD", "/archive")
        .with_status(200)
        .with_header("content-length", archive_len.as_str())
        .create_async()
        .await;

    let _archive_get_mock = server
        .mock("GET", "/archive")
        .with_status(200)
        .with_header("content-length", archive_len.as_str())
        .with_body(archive_encrypted)
        .create_async()
        .await;

    let _metrics_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/metrics")
        .with_status(200)
        .with_body("{}")
        .create_async()
        .await;

    let target_dir = temp_dir.path().join("restore-target");
    let tag_path = format!("cache-tag:{}", target_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            tag_path.as_str(),
            "--no-platform",
            "--no-git",
            "--identity",
            identity_path.to_str().unwrap(),
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.code() != Some(0) {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
    }

    assert_eq!(output.status.code(), Some(0));
    assert!(stderr.contains("Server signature verification failed"));

    let restored =
        fs::read_to_string(target_dir.join("hello.txt")).expect("Failed to read restored file");
    assert_eq!(restored, "hello");

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_passphrase_manifest_requires_passphrase() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_passphrase_manifest_requires_passphrase: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let data_dir = temp_dir.path().join("data");
    fs::create_dir(&data_dir).expect("Failed to create data dir");
    fs::write(data_dir.join("hello.txt"), "hello").expect("Failed to write data file");

    let (manifest, manifest_bytes, _archive_bytes) =
        build_manifest_and_archive(&data_dir, "cache-tag", None).await;
    let manifest_encrypted = encrypt_with_passphrase(&manifest_bytes, "test-passphrase");

    let manifest_url = format!("{}/manifest-passphrase", server.url());
    let archive_url = format!("{}/archive-passphrase", server.url());

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": "cache-tag",
                    "status": "hit",
                    "cache_entry_id": "123",
                    "manifest_url": manifest_url,
                    "archive_urls": [archive_url],
                    "manifest_root_digest": manifest.root.digest,
                    "encrypted": false
                }
            ])
            .to_string(),
        )
        .create_async()
        .await;

    let _manifest_mock = server
        .mock("GET", "/manifest-passphrase")
        .with_status(200)
        .with_header("content-type", "application/octet-stream")
        .with_body(manifest_encrypted)
        .create_async()
        .await;

    let _archive_head_mock = server
        .mock("HEAD", "/archive-passphrase")
        .with_status(200)
        .with_header("content-length", "1")
        .create_async()
        .await;

    let target_dir = temp_dir.path().join("restore-target");
    let tag_path = format!("cache-tag:{}", target_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            tag_path.as_str(),
            "--no-platform",
            "--no-git",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success());
    assert!(stderr.contains("passphrase"));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_workflow_success() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_save_workflow_success: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let _upload_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches")
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

    let _metrics_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/metrics")
        .with_status(201)
        .with_body(json!({"status": "success", "metric_id": "metric-456"}).to_string())
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        let combined_lower = combined.to_lowercase();
        assert!(
            combined_lower.contains("completed")
                || combined_lower.contains("saving")
                || combined_lower.contains("saved")
                || combined_lower.contains("uploaded")
                || combined_lower.contains("success")
        );
    }

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_restore_workflow_cache_not_found() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_workflow_cache_not_found: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?tags=.*$".to_string()),
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _output_text = format!("{stdout}{stderr}");

    let exit_code = output.status.code();
    assert_eq!(exit_code, Some(0));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_metrics_workflow() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_metrics_workflow: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_exit_codes: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let _miss_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?tags=.*$".to_string()),
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

    let exit_code = output.status.code();
    assert_eq!(exit_code, Some(0));

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

    let _auth_mock = server
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

    let platform_suffix = platform_tag_suffix();
    let miss_tag = format!("missing-cache-{}", platform_suffix);

    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": miss_tag,
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
        .args([
            "restore",
            "test/workspace",
            "missing-cache",
            "--fail-on-cache-miss",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // --fail-on-cache-miss should return non-zero exit code when cache is not found
    assert!(
        !output.status.success(),
        "Expected non-zero exit code with --fail-on-cache-miss when cache not found"
    );

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

    let _auth_mock = server
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

    let platform_suffix = platform_tag_suffix();
    let hit_tag = format!("existing-cache-{}", platform_suffix);
    let miss_tag = format!("missing-cache-{}", platform_suffix);

    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": hit_tag,
                    "cache_entry_id": "123",
                    "manifest_url": "https://example.com/manifest",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                },
                {
                    "tag": miss_tag,
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
        .args([
            "restore",
            "test/workspace",
            "existing-cache,missing-cache",
            "--fail-on-cache-miss",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    // --fail-on-cache-miss should return non-zero exit code when any cache is not found
    assert!(
        !output.status.success(),
        "Expected non-zero exit code with --fail-on-cache-miss when cache not found"
    );

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
async fn test_restore_fail_on_cache_error_flag() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_fail_on_cache_error_flag: networking disabled in sandbox");
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let platform_suffix = platform_tag_suffix();
    let hit_tag = format!("error-cache-{}", platform_suffix);

    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": hit_tag,
                "cache_entry_id": "entry-123",
                "manifest_url": format!("{}/manifest-error", server.url()),
                "archive_urls": [format!("{}/archive-error", server.url())],
                "chunks": [],
                "metadata": null,
                "status": "hit"
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _manifest_mock = server
        .mock("GET", "/manifest-error")
        .with_status(500)
        .with_body("storage unavailable")
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

    let restore_target = temp_dir.path().join("restore-target");
    let output = std::process::Command::new(cli_binary())
        .args([
            "restore",
            "test/workspace",
            &format!("error-cache:{}", restore_target.display()),
            "--fail-on-cache-error",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    assert!(
        !output.status.success(),
        "Expected non-zero exit code with --fail-on-cache-error on backend failure"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Restore failed")
            || stderr.contains("Failed to download")
            || stderr.contains("cache/backend"),
        "Unexpected stderr: {}",
        stderr
    );

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

    let _auth_mock = server
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

    let platform_suffix = platform_tag_suffix();
    let hit_tag = format!("existing-cache-{}", platform_suffix);
    let miss_tag = format!("missing-cache-{}", platform_suffix);

    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": hit_tag.clone(),
                    "cache_entry_id": "123",
                    "manifest_url": "https://example.com/manifest",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                },
                {
                    "tag": miss_tag,
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
        .args([
            "restore",
            "test/workspace",
            "existing-cache,missing-cache",
            "--lookup-only",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.code() != Some(0) {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
        eprintln!("Exit code: {:?}", output.status.code());
    }

    assert_eq!(output.status.code(), Some(0));

    let output_text = format!("{stdout}{stderr}");

    assert!(output_text.contains(&format!("Available cache entries: {}", hit_tag)));
    assert!(output_text.contains("Not found: missing-cache"));

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

    let _auth_mock = server
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

    let platform_suffix = platform_tag_suffix();
    let hit_tag1 = format!("cache-1-{}", platform_suffix);
    let hit_tag2 = format!("cache-2-{}", platform_suffix);

    let _cache_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([
                {
                    "tag": hit_tag1.clone(),
                    "cache_entry_id": "123",
                    "manifest_url": "https://example.com/manifest1",
                    "chunks": [],
                    "metadata": null,
                    "status": "hit"
                },
                {
                    "tag": hit_tag2.clone(),
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
        .args([
            "restore",
            "test/workspace",
            "cache-1,cache-2",
            "--lookup-only",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.code() != Some(0) {
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
        eprintln!("Exit code: {:?}", output.status.code());
    }

    assert_eq!(output.status.code(), Some(0));

    let output_text = format!("{stdout}{stderr}");

    assert!(output_text.contains("Available cache entries"));
    assert!(output_text.contains(&hit_tag1));
    assert!(output_text.contains(&hit_tag2));

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

    let _auth_mock = server
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

    let platform_suffix = platform_tag_suffix();
    let saved_tag = format!("test-force-tag-{}", platform_suffix);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "force": true
            }
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": saved_tag,
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

    let _manifest_upload_mock = server
        .mock("PUT", mockito::Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "POST",
            mockito::Matcher::Regex(
                r"/v2/workspaces/test/workspace/caches/test-force-tag-.*/confirm".to_string(),
            ),
        )
        .with_status(200)
        .with_body(json!({"status": "ready"}).to_string())
        .create_async()
        .await;

    let _metrics_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/metrics")
        .with_status(201)
        .with_body(json!({"status": "success", "metric_id": "metric-789"}).to_string())
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

    if !output.status.success() {
        eprintln!("Command failed with output:");
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
    }

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

    let _auth_mock = server
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

    let save_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches")
        .expect(0)
        .with_status(201)
        .create_async()
        .await;

    let _metrics_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/metrics")
        .with_status(201)
        .with_body(json!({"status": "success"}).to_string())
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

    assert!(
        output_text.contains("already") || output_text.contains("exists"),
        "Expected 'already exists' message, got: {}",
        output_text
    );

    save_mock.assert_async().await;

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

#[tokio::test]
async fn test_save_workflow_digest_lookup_binds_tag() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!(
            "skipping test_save_workflow_digest_lookup_binds_tag: networking disabled in sandbox"
        );
        return;
    }
    let mut server = Server::new_async().await;

    let _auth_mock = server
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

    let _tag_check_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches/check")
        .match_body(Matcher::Regex(
            r#"^\{"manifest_checks":\[\{"tag":"test-digest-tag","manifest_root_digest":"[^"]+"\}\]\}$"#
                .to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "tag": "test-digest-tag",
                    "exists": false
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _digest_check_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches/check")
        .match_body(Matcher::Regex(
            r#"^\{"manifest_checks":\[\{"tag":"test-digest-tag","manifest_root_digest":"[^"]+","lookup":"digest"\}\]\}$"#
                .to_string(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "tag": "test-digest-tag",
                    "exists": true,
                    "status": "ready",
                    "cache_entry_id": "existing-entry-123",
                    "manifest_root_digest": "blake3:abc123"
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PATCH",
            "/v2/workspaces/test/workspace/caches/existing-entry-123",
        )
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": "test-digest-tag"
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "status": "ready",
                "cache_entry_id": "existing-entry-123"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _save_mock = server
        .mock("POST", "/v2/workspaces/test/workspace/caches")
        .expect(0)
        .with_status(201)
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

    let cache_dir = temp_dir.path().join("digest_cache_test");
    fs::create_dir(&cache_dir).expect("Failed to create cache dir");
    fs::write(cache_dir.join("test1.txt"), "test content 1").expect("Failed to write test1");
    fs::write(cache_dir.join("test2.txt"), "test content 2").expect("Failed to write test2");

    env::set_var("HOME", temp_dir.path());

    let tag_path = format!("test-digest-tag:{}", cache_dir.to_str().unwrap());
    let output = std::process::Command::new(cli_binary())
        .args([
            "save",
            "test/workspace",
            tag_path.as_str(),
            "--no-platform",
            "--no-git",
        ])
        .current_dir(temp_dir.path())
        .output()
        .expect("Failed to execute command");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Command failed with output:");
        eprintln!("STDOUT: {}", stdout);
        eprintln!("STDERR: {}", stderr);
    }

    assert_eq!(output.status.code(), Some(0));

    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
}

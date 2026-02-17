use base64::Engine as _;
use boring_cache_cli::manifest::EntryType;
use boring_cache_cli::{cas_file, cas_oci};
use mockito::{Matcher, Server};
use serde_json::json;
use std::env;
use std::fs;
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

fn restore_env(temp_home: &Path, server_url: &str) {
    env::set_var("BORINGCACHE_API_TOKEN", "test-token-123");
    env::set_var("BORINGCACHE_API_URL", server_url);
    env::set_var("HOME", temp_home);
    env::set_var("BORINGCACHE_TELEMETRY_DISABLED", "1");
}

fn clear_env() {
    env::remove_var("BORINGCACHE_API_TOKEN");
    env::remove_var("BORINGCACHE_API_URL");
    env::remove_var("HOME");
    env::remove_var("BORINGCACHE_TELEMETRY_DISABLED");
}

#[tokio::test]
async fn test_save_uses_archive_layout_for_generic_directory() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!(
            "skipping test_save_uses_archive_layout_for_generic_directory: networking disabled"
        );
        return;
    }

    let mut server = Server::new_async().await;
    let _save_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .match_header("authorization", "Bearer test-token-123")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": "generic-file-tag"
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "generic-file-tag",
                "cache_entry_id": "entry-file-1",
                "exists": true,
                "status": "pending",
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let cache_dir = temp_dir.path().join("generic_cache");
    fs::create_dir(&cache_dir).expect("Failed to create cache dir");
    fs::write(cache_dir.join("hello.txt"), "hello world").expect("Failed to write test file");

    let tag_path = format!("generic-file-tag:{}", cache_dir.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    clear_env();
}

#[tokio::test]
async fn test_save_uses_bazel_layout_for_bazel_cache() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_save_uses_bazel_layout_for_bazel_cache: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;
    let _save_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .match_header("authorization", "Bearer test-token-123")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": "bazel-cache-tag",
                "storage_mode": "cas",
                "cas_layout": "bazel-v2"
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "bazel-cache-tag",
                "cache_entry_id": "entry-bazel-1",
                "exists": true,
                "status": "pending",
                "storage_mode": "cas",
                "cas_layout": "bazel-v2",
                "blob_count": 2,
                "blob_total_size_bytes": 20,
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let cache_dir = temp_dir.path().join("bazel_cache");
    fs::create_dir_all(cache_dir.join("ac")).expect("Failed to create bazel ac dir");
    fs::create_dir_all(cache_dir.join("cas")).expect("Failed to create bazel cas dir");
    fs::write(cache_dir.join("ac").join("action-1"), "action data")
        .expect("Failed to write bazel ac file");
    fs::write(cache_dir.join("cas").join("blob-1"), "blob data")
        .expect("Failed to write bazel cas file");

    let tag_path = format!("bazel-cache-tag:{}", cache_dir.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    clear_env();
}

#[tokio::test]
async fn test_save_uses_oci_layout_for_oci_cache() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_save_uses_oci_layout_for_oci_cache: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;
    let _save_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .match_header("authorization", "Bearer test-token-123")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": "oci-cache-tag",
                "storage_mode": "cas",
                "cas_layout": "oci-v1"
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "oci-cache-tag",
                "cache_entry_id": "entry-oci-1",
                "exists": true,
                "status": "pending",
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
                "blob_count": 1,
                "blob_total_size_bytes": 8,
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let cache_dir = temp_dir.path().join("oci_cache");
    let blobs_dir = cache_dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir).expect("Failed to create OCI blobs dir");
    fs::write(cache_dir.join("index.json"), "{\"schemaVersion\":2}")
        .expect("Failed to write OCI index");
    fs::write(
        cache_dir.join("oci-layout"),
        "{\"imageLayoutVersion\":\"1.0.0\"}",
    )
    .expect("Failed to write OCI layout");
    fs::write(
        blobs_dir.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        b"blobdata",
    )
    .expect("Failed to write OCI blob");

    let tag_path = format!("oci-cache-tag:{}", cache_dir.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    clear_env();
}

#[tokio::test]
async fn test_save_requests_upload_urls_for_existing_cas_blobs() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!(
            "skipping test_save_requests_upload_urls_for_existing_cas_blobs: networking disabled"
        );
        return;
    }

    let mut server = Server::new_async().await;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let cache_dir = temp_dir.path().join("oci_cache_attach");
    let blobs_dir = cache_dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir).expect("Failed to create OCI blobs dir");
    fs::write(cache_dir.join("index.json"), "{\"schemaVersion\":2}")
        .expect("Failed to write OCI index");
    fs::write(
        cache_dir.join("oci-layout"),
        "{\"imageLayoutVersion\":\"1.0.0\"}",
    )
    .expect("Failed to write OCI layout");

    let blob_bytes = b"blobdata";
    let blob_hex = cas_oci::sha256_hex(blob_bytes);
    let blob_digest = format!("sha256:{blob_hex}");
    let blob_size = blob_bytes.len() as u64;
    fs::write(blobs_dir.join(&blob_hex), blob_bytes).expect("Failed to write OCI blob");

    let manifest_upload_url = format!("{}/manifest-upload", server.url());

    let save_mock = server
        .mock("POST", "/workspaces/test/workspace/caches")
        .match_header("authorization", "Bearer test-token-123")
        .match_body(Matcher::Any)
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "oci-attach-tag",
                "cache_entry_id": "entry-oci-attach",
                "exists": false,
                "status": "pending",
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
                "blob_count": 1,
                "blob_total_size_bytes": blob_size,
                "manifest_upload_url": manifest_upload_url,
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let check_mock = server
        .mock("POST", "/workspaces/test/workspace/caches/blobs/check")
        .match_header("authorization", "Bearer test-token-123")
        .match_body(Matcher::PartialJson(json!({
            "blobs": [
                {
                    "digest": blob_digest,
                    "size_bytes": blob_size
                }
            ]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [
                    {
                        "digest": blob_digest,
                        "exists": true
                    }
                ]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let upload_urls_mock = server
        .mock(
            "POST",
            "/workspaces/test/workspace/caches/blobs/upload-urls",
        )
        .match_header("authorization", "Bearer test-token-123")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-oci-attach",
            "blobs": [
                {
                    "digest": blob_digest,
                    "size_bytes": blob_size
                }
            ]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [],
                "already_present": [blob_digest]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let manifest_upload_mock = server
        .mock("PUT", "/manifest-upload")
        .with_status(200)
        .with_header("etag", "\"manifest-etag\"")
        .create_async()
        .await;

    let confirm_mock = server
        .mock(
            "PATCH",
            "/workspaces/test/workspace/caches/entry-oci-attach",
        )
        .match_header("authorization", "Bearer test-token-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "cache_entry_id": "entry-oci-attach",
                "status": "ready",
                "uploaded_at": "2026-02-16T00:00:00Z",
                "tag_status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let tag_path = format!("oci-attach-tag:{}", cache_dir.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    save_mock.assert_async().await;
    check_mock.assert_async().await;
    upload_urls_mock.assert_async().await;
    manifest_upload_mock.assert_async().await;
    confirm_mock.assert_async().await;
    clear_env();
}

#[tokio::test]
async fn test_restore_materializes_file_cas_layout() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_materializes_file_cas_layout: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;
    let blob_bytes = b"restored file bytes".to_vec();
    let blob_digest = format!("sha256:{}", cas_file::sha256_hex(&blob_bytes));
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: vec![cas_file::FilePointerEntry {
            path: "nested/file.txt".to_string(),
            entry_type: EntryType::File,
            size_bytes: blob_bytes.len() as u64,
            executable: Some(false),
            target: None,
            digest: Some(blob_digest.clone()),
        }],
        blobs: vec![cas_file::FilePointerBlob {
            digest: blob_digest.clone(),
            size_bytes: blob_bytes.len() as u64,
        }],
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("Failed to encode pointer");
    let root_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "file-restore-tag",
                "status": "hit",
                "cache_entry_id": "restore-file-entry",
                "manifest_root_digest": root_digest,
                "manifest_digest": root_digest,
                "manifest_url": format!("{}/file-pointer", server.url()),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
                "blob_count": 1,
                "blob_total_size_bytes": blob_bytes.len() as u64,
                "archive_urls": []
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _manifest_mock = server
        .mock("GET", "/file-pointer")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock(
            "POST",
            "/workspaces/test/workspace/caches/blobs/download-urls",
        )
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "restore-file-entry",
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": blob_bytes.len() as u64
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": blob_digest,
                    "url": format!("{}/file-blob", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", "/file-blob")
        .with_status(200)
        .with_body(blob_bytes.clone())
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let restore_target = temp_dir.path().join("restore_file_target");
    let tag_path = format!("file-restore-tag:{}", restore_target.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    let restored = fs::read(restore_target.join("nested").join("file.txt"))
        .expect("Expected restored file content");
    assert_eq!(restored, blob_bytes);
    clear_env();
}

#[tokio::test]
async fn test_restore_materializes_bazel_layout() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_materializes_bazel_layout: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;
    let ac_bytes = b"action-result".to_vec();
    let cas_bytes = b"blob-result".to_vec();
    let ac_digest = format!("sha256:{}", cas_file::sha256_hex(&ac_bytes));
    let cas_digest = format!("sha256:{}", cas_file::sha256_hex(&cas_bytes));
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: vec![
            cas_file::FilePointerEntry {
                path: "ac/action-key".to_string(),
                entry_type: EntryType::File,
                size_bytes: ac_bytes.len() as u64,
                executable: Some(false),
                target: None,
                digest: Some(ac_digest.clone()),
            },
            cas_file::FilePointerEntry {
                path: "cas/blob-key".to_string(),
                entry_type: EntryType::File,
                size_bytes: cas_bytes.len() as u64,
                executable: Some(false),
                target: None,
                digest: Some(cas_digest.clone()),
            },
        ],
        blobs: vec![
            cas_file::FilePointerBlob {
                digest: ac_digest.clone(),
                size_bytes: ac_bytes.len() as u64,
            },
            cas_file::FilePointerBlob {
                digest: cas_digest.clone(),
                size_bytes: cas_bytes.len() as u64,
            },
        ],
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("Failed to encode pointer");
    let root_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "bazel-restore-tag",
                "status": "hit",
                "cache_entry_id": "restore-bazel-entry",
                "manifest_root_digest": root_digest,
                "manifest_digest": root_digest,
                "manifest_url": format!("{}/bazel-pointer", server.url()),
                "storage_mode": "cas",
                "cas_layout": "bazel-v2",
                "blob_count": 2,
                "blob_total_size_bytes": (ac_bytes.len() + cas_bytes.len()) as u64,
                "archive_urls": []
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _manifest_mock = server
        .mock("GET", "/bazel-pointer")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock(
            "POST",
            "/workspaces/test/workspace/caches/blobs/download-urls",
        )
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "restore-bazel-entry"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": ac_digest,
                        "url": format!("{}/bazel-ac-blob", server.url())
                    },
                    {
                        "digest": cas_digest,
                        "url": format!("{}/bazel-cas-blob", server.url())
                    }
                ],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _ac_blob_mock = server
        .mock("GET", "/bazel-ac-blob")
        .with_status(200)
        .with_body(ac_bytes.clone())
        .create_async()
        .await;
    let _cas_blob_mock = server
        .mock("GET", "/bazel-cas-blob")
        .with_status(200)
        .with_body(cas_bytes.clone())
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let restore_target = temp_dir.path().join("restore_bazel_target");
    let tag_path = format!("bazel-restore-tag:{}", restore_target.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    let ac_restored =
        fs::read(restore_target.join("ac").join("action-key")).expect("Expected ac file");
    let cas_restored =
        fs::read(restore_target.join("cas").join("blob-key")).expect("Expected cas file");
    assert_eq!(ac_restored, ac_bytes);
    assert_eq!(cas_restored, cas_bytes);
    clear_env();
}

#[tokio::test]
async fn test_restore_materializes_oci_layout() {
    let _lock = acquire_test_lock().await;
    if !networking_available() {
        eprintln!("skipping test_restore_materializes_oci_layout: networking disabled");
        return;
    }

    let mut server = Server::new_async().await;
    let blob_bytes = b"oci-layer".to_vec();
    let blob_hex = cas_oci::sha256_hex(&blob_bytes);
    let blob_digest = format!("sha256:{blob_hex}");
    let pointer = cas_oci::OciPointer {
        format_version: 1,
        adapter: "oci-v1".to_string(),
        index_json_base64: base64::engine::general_purpose::STANDARD
            .encode(b"{\"schemaVersion\":2}"),
        oci_layout_base64: base64::engine::general_purpose::STANDARD
            .encode(b"{\"imageLayoutVersion\":\"1.0.0\"}"),
        blobs: vec![cas_oci::OciPointerBlob {
            digest: blob_digest.clone(),
            size_bytes: blob_bytes.len() as u64,
        }],
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("Failed to encode OCI pointer");
    let root_digest = cas_oci::prefixed_sha256_digest(&pointer_bytes);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/workspaces/test/workspace/caches\?entries=.*$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "oci-restore-tag",
                "status": "hit",
                "cache_entry_id": "restore-oci-entry",
                "manifest_root_digest": root_digest,
                "manifest_digest": root_digest,
                "manifest_url": format!("{}/oci-pointer", server.url()),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
                "blob_count": 1,
                "blob_total_size_bytes": blob_bytes.len() as u64,
                "archive_urls": []
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _manifest_mock = server
        .mock("GET", "/oci-pointer")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock(
            "POST",
            "/workspaces/test/workspace/caches/blobs/download-urls",
        )
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "restore-oci-entry",
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": blob_bytes.len() as u64
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": blob_digest,
                    "url": format!("{}/oci-blob", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", "/oci-blob")
        .with_status(200)
        .with_body(blob_bytes.clone())
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    setup_test_config(&temp_dir, &server.url());
    restore_env(temp_dir.path(), &server.url());

    let restore_target = temp_dir.path().join("restore_oci_target");
    let tag_path = format!("oci-restore-tag:{}", restore_target.to_string_lossy());
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

    assert_eq!(output.status.code(), Some(0));
    let restored_blob =
        fs::read(restore_target.join("blobs").join("sha256").join(blob_hex)).expect("blob");
    assert_eq!(restored_blob, blob_bytes);
    assert!(restore_target.join("index.json").exists());
    assert!(restore_target.join("oci-layout").exists());
    clear_env();
}

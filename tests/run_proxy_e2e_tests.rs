#![cfg(unix)]

use mockito::{Matcher, Server};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const DUMMY_API_URL: &str = "http://127.0.0.1:65535";

fn cli_binary() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_boringcache")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_boringcache").map(PathBuf::from))
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap()
                .join("target/debug/boringcache")
        })
}

fn canonical_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[test]
fn test_run_proxy_injects_env_and_substitutes_placeholders() {
    let temp_dir = TempDir::new().expect("temp dir");
    let script = r#"expected_endpoint="http://127.0.0.1:$1"
expected_ref="127.0.0.1:$1/cache:main"
expected_sccache_endpoint="${expected_endpoint}/"
[ "${NX_SELF_HOSTED_REMOTE_CACHE_SERVER:-}" = "$expected_endpoint" ] || exit 2
[ "${TURBO_API:-}" = "$expected_endpoint" ] || exit 3
[ "${SCCACHE_WEBDAV_ENDPOINT:-}" = "$expected_sccache_endpoint" ] || exit 4
[ "${SCCACHE_ENDPOINT:-}" = "https://wrong.example.invalid" ] || exit 5
[ "${SCCACHE_BUCKET:-}" = "wrong-bucket" ] || exit 6
[ "${SCCACHE_WEBDAV_USERNAME:-}" = "wrong-user" ] || exit 7
[ "${SCCACHE_WEBDAV_PASSWORD:-}" = "wrong-password" ] || exit 8
[ "${SCCACHE_CONF:-}" = "/tmp/wrong-sccache.conf" ] || exit 9
[ "${SCCACHE_CACHED_CONF:-}" = "stale-config" ] || exit 10
[ "${SCCACHE_WEBDAV_TOKEN:-}" = "wrong-token" ] || exit 11
[ "${2:-}" = "$expected_ref" ] || exit 12
status_headers="$(curl -fsS -D - -o /dev/null --max-time 2 "$expected_endpoint/_boringcache/status")" || exit 13
phase="$(printf '%s\n' "$status_headers" | awk -F': ' 'tolower($1) == "x-boringcache-proxy-phase" { gsub("\\r", "", $2); print tolower($2); exit }')"
[ "$phase" = "ready" ] || exit 14
"#;

    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "main",
            "--on-demand",
            "--no-platform",
            "--no-git",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--",
            "sh",
            "-ec",
            script,
            "_",
            "{PORT}",
            "{CACHE_REF}",
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_SAVE_TOKEN", "test-save-token")
        .env("SCCACHE_ENDPOINT", "https://wrong.example.invalid")
        .env("SCCACHE_BUCKET", "wrong-bucket")
        .env("SCCACHE_WEBDAV_USERNAME", "wrong-user")
        .env("SCCACHE_WEBDAV_PASSWORD", "wrong-password")
        .env("SCCACHE_CONF", "/tmp/wrong-sccache.conf")
        .env("SCCACHE_CACHED_CONF", "stale-config")
        .env("SCCACHE_WEBDAV_TOKEN", "wrong-token")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .output()
        .expect("run proxy command");

    assert!(
        output.status.success(),
        "Expected successful run --proxy e2e, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_run_proxy_propagates_child_exit_code() {
    let temp_dir = TempDir::new().expect("temp dir");
    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "main",
            "--on-demand",
            "--no-platform",
            "--no-git",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--",
            "sh",
            "-c",
            "exit 19",
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_SAVE_TOKEN", "test-save-token")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .output()
        .expect("run proxy command");

    assert_eq!(
        output.status.code(),
        Some(19),
        "Expected child exit code propagation in proxy mode, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_run_combined_archive_and_proxy_mode_executes_child() {
    let temp_dir = TempDir::new().expect("temp dir");
    let cache_dir = temp_dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let script = r#"expected_endpoint="http://127.0.0.1:$1"
[ "${NX_SELF_HOSTED_REMOTE_CACHE_SERVER:-}" = "$expected_endpoint" ] || exit 2
status_headers="$(curl -fsS -D - -o /dev/null --max-time 2 "$expected_endpoint/_boringcache/status")" || exit 3
phase="$(printf '%s\n' "$status_headers" | awk -F': ' 'tolower($1) == "x-boringcache-proxy-phase" { gsub("\\r", "", $2); print tolower($2); exit }')"
[ "$phase" = "ready" ] || exit 4
"#;

    let pair = format!("deps:{}", cache_dir.display());
    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            &pair,
            "--proxy",
            "main",
            "--on-demand",
            "--skip-restore",
            "--skip-save",
            "--no-platform",
            "--no-git",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--",
            "sh",
            "-ec",
            script,
            "_",
            "{PORT}",
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_SAVE_TOKEN", "test-save-token")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .output()
        .expect("run combined command");

    assert!(
        output.status.success(),
        "Expected successful combined run mode, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_run_proxy_warm_start_continues_when_backend_cannot_hydrate() {
    let temp_dir = TempDir::new().expect("temp dir");
    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "main",
            "--no-platform",
            "--no-git",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--",
            "sh",
            "-c",
            "printf launched",
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_SAVE_TOKEN", "test-save-token")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .output()
        .expect("run proxy command");

    assert!(
        output.status.success(),
        "Expected warm proxy startup to launch command after failed warm attempt, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("launched"),
        "Command should launch after failed warm attempt, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_run_proxy_upserts_direct_kv_rows() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut server = Server::new();
    let workspace_path = "/v2/workspaces/test-org/test-workspace";
    let payload = b"provider-neutral-artifact";
    let digest = canonical_digest(payload);
    let metadata_digest = canonical_digest(b"{}");

    let stage_mock = server
        .mock(
            "POST",
            format!("{workspace_path}/caches/blobs/stage").as_str(),
        )
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": digest,
                    "url": format!("{}/provider-neutral-upload", server.url()),
                    "headers": {}
                }, {
                    "digest": metadata_digest,
                    "url": format!("{}/provider-neutral-metadata-upload", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let blob_upload_mock = server
        .mock("PUT", "/provider-neutral-upload")
        .match_body(Matcher::Exact("provider-neutral-artifact".to_string()))
        .with_status(200)
        .expect(1)
        .create();
    let metadata_upload_mock = server
        .mock("PUT", "/provider-neutral-metadata-upload")
        .match_body(Matcher::Exact("{}".to_string()))
        .with_status(200)
        .expect(1)
        .create();

    let kv_upsert_mock = server
        .mock("POST", format!("{workspace_path}/cache-kv-entries").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Any)
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "entries": [{
                    "namespace": "turbo",
                    "scoped_key": "turbo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "blob": { "digest": digest, "size_bytes": payload.len() }
                }, {
                    "namespace": "turbo_meta",
                    "scoped_key": "turbo_meta/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "blob": { "digest": metadata_digest, "size_bytes": 2 }
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let save_mock = server
        .mock("POST", format!("{workspace_path}/caches").as_str())
        .expect(0)
        .create();
    let rollup_mock = server
        .mock("POST", format!("{workspace_path}/cache-rollups").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Regex(
            r#""run_provider":"gitlab".*"cache_kv_entries_upsert""#.to_string(),
        ))
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(json!({"accepted": true}).to_string())
        .expect(1)
        .create();

    let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let script = r#"endpoint="http://127.0.0.1:$1"
hash="$2"
curl -fsS \
  -X PUT \
  -H "Authorization: Bearer proxy-token" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "provider-neutral-artifact" \
  "$endpoint/v8/artifacts/$hash" >/dev/null
"#;

    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "main",
            "--on-demand",
            "--no-platform",
            "--no-git",
            "--fail-on-cache-error",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--",
            "sh",
            "-ec",
            script,
            "_",
            "{PORT}",
            hash,
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", server.url())
        .env("BORINGCACHE_SAVE_TOKEN", "test-save-token")
        .env("BORINGCACHE_CI_PROVIDER", "gitlab")
        .env("BORINGCACHE_CI_RUN_ID", "pipeline-987")
        .env("BORINGCACHE_CI_RUN_ATTEMPT", "2")
        .env("BORINGCACHE_CI_REF_TYPE", "branch")
        .env("BORINGCACHE_CI_REF_NAME", "main")
        .env("BORINGCACHE_CI_DEFAULT_BRANCH", "main")
        .env(
            "BORINGCACHE_CI_SHA",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .env("BORINGCACHE_CI_RUN_STARTED_AT", "2026-04-22T09:00:00Z")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITHUB_RUN_ID")
        .output()
        .expect("run proxy command");

    assert!(
        output.status.success(),
        "Expected direct KV proxy save e2e to succeed, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    stage_mock.assert();
    blob_upload_mock.assert();
    metadata_upload_mock.assert();
    kv_upsert_mock.assert();
    save_mock.assert();
    rollup_mock.assert();
}

#[test]
fn test_run_proxy_direct_kv_flush_skips_manifest_publish() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut server = Server::new();
    let workspace_path = "/v2/workspaces/test-org/test-workspace";
    let payload = b"contended-artifact";
    let digest = canonical_digest(payload);
    let metadata_digest = canonical_digest(b"{}");

    let stage_mock = server
        .mock(
            "POST",
            format!("{workspace_path}/caches/blobs/stage").as_str(),
        )
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": digest,
                    "url": format!("{}/direct-kv-upload", server.url()),
                    "headers": {}
                }, {
                    "digest": metadata_digest,
                    "url": format!("{}/direct-kv-metadata-upload", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let blob_upload_mock = server
        .mock("PUT", "/direct-kv-upload")
        .match_body(Matcher::Exact("contended-artifact".to_string()))
        .with_status(200)
        .expect(1)
        .create();
    let metadata_upload_mock = server
        .mock("PUT", "/direct-kv-metadata-upload")
        .match_body(Matcher::Exact("{}".to_string()))
        .with_status(200)
        .expect(1)
        .create();

    let kv_upsert_mock = server
        .mock("POST", format!("{workspace_path}/cache-kv-entries").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Any)
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "entries": [{
                    "namespace": "turbo",
                    "scoped_key": "turbo/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "blob": { "digest": digest, "size_bytes": payload.len() }
                }, {
                    "namespace": "turbo_meta",
                    "scoped_key": "turbo_meta/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "blob": { "digest": metadata_digest, "size_bytes": 2 }
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let save_mock = server
        .mock("POST", format!("{workspace_path}/caches").as_str())
        .expect(0)
        .create();
    let publish_mock = server
        .mock(
            "PUT",
            format!("{workspace_path}/caches/tags/main/publish").as_str(),
        )
        .expect(0)
        .create();
    let rollup_mock = server
        .mock("POST", format!("{workspace_path}/cache-rollups").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Regex(
            r#""cache_kv_entries_upsert".*"kv_upload_uploaded_blobs":2"#.to_string(),
        ))
        .with_status(202)
        .with_header("content-type", "application/json")
        .with_body(json!({"accepted": true}).to_string())
        .expect(1)
        .create();

    let hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let script = r#"endpoint="http://127.0.0.1:$1"
hash="$2"
curl -fsS \
  -X PUT \
  -H "Authorization: Bearer proxy-token" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "contended-artifact" \
  "$endpoint/v8/artifacts/$hash" >/dev/null
"#;

    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "main",
            "--on-demand",
            "--no-platform",
            "--no-git",
            "--fail-on-cache-error",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--",
            "sh",
            "-ec",
            script,
            "_",
            "{PORT}",
            hash,
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", server.url())
        .env("BORINGCACHE_SAVE_TOKEN", "test-save-token")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .output()
        .expect("run proxy command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Expected proxy run to upsert direct KV rows without manifest publish, stdout: {stdout}, stderr: {stderr}"
    );

    stage_mock.assert();
    blob_upload_mock.assert();
    metadata_upload_mock.assert();
    kv_upsert_mock.assert();
    save_mock.assert();
    publish_mock.assert();
    rollup_mock.assert();
}

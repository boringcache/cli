#![cfg(unix)]

use mockito::{Matcher, Server};
use serde_json::json;
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
fn test_run_proxy_sends_provider_neutral_ci_context_to_save_request() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut server = Server::new();
    let tag = "main";
    let workspace_path = "/v2/workspaces/test-org/test-workspace";
    let pointer_path = format!("{workspace_path}/caches/tags/{tag}/pointer");
    let publish_path = format!("{workspace_path}/caches/tags/{tag}/publish");

    let capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .match_header("authorization", "Bearer test-save-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "features": {
                    "tag_publish_v2": true,
                    "cas_publish_bootstrap_if_match": "0"
                }
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let save_mock = server
        .mock("POST", format!("{workspace_path}/caches").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": tag,
                "write_scope_tag": "main",
                "storage_mode": "cas",
                "cas_layout": "file-v1",
                "ci_provider": "gitlab",
                "ci_run_uid": "pipeline-987",
                "ci_run_attempt": "2",
                "ci_ref_type": "branch",
                "ci_ref_name": "main",
                "ci_default_branch": "main",
                "ci_commit_sha": "0123456789abcdef0123456789abcdef01234567",
                "ci_run_started_at": "2026-04-22T09:00:00Z"
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": tag,
                "cache_entry_id": "entry-provider-neutral",
                "exists": true,
                "storage_mode": "cas",
                "blob_count": 2,
                "blob_total_size_bytes": 24,
                "cas_layout": "file-v1"
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let stage_mock = server
        .mock(
            "POST",
            format!("{workspace_path}/caches/blobs/stage").as_str(),
        )
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"upload_urls": [], "already_present": []}).to_string())
        .expect(1)
        .create();

    let pointer_mock = server
        .mock("GET", pointer_path.as_str())
        .match_header("authorization", "Bearer test-save-token")
        .with_status(404)
        .expect(1)
        .create();
    let publish_mock = server
        .mock("PUT", publish_path.as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_header("if-match", "0")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-provider-neutral",
            "publish_mode": "cas",
            "write_scope_tag": "main"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "1",
                "cache_entry_id": "entry-provider-neutral",
                "status": "ready"
            })
            .to_string(),
        )
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
        "Expected provider-neutral CI proxy save e2e to succeed, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    capabilities_mock.assert();
    save_mock.assert();
    stage_mock.assert();
    pointer_mock.assert();
    publish_mock.assert();
}

#[test]
fn test_run_proxy_shutdown_retries_upload_in_progress_contention() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut server = Server::new();
    let workspace_path = "/v2/workspaces/test-org/test-workspace";
    let alias_pointer_path = format!("{workspace_path}/caches/tags/main/pointer");
    let alias_publish_path = format!("{workspace_path}/caches/tags/main/publish");

    let _capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .match_header("authorization", "Bearer test-save-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "features": {
                    "tag_publish_v2": true,
                    "registry_path_tags": true,
                    "cas_publish_bootstrap_if_match": "0"
                }
            })
            .to_string(),
        )
        .expect_at_least(1)
        .create();

    let contended_save_mock = server
        .mock("POST", format!("{workspace_path}/caches").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "main",
                "cache_entry_id": "entry-pending-owner",
                "exists": true,
                "status": "pending",
                "storage_mode": "cas",
                "cas_layout": "file-v1",
                "manifest_root_digest": "sha256:foreign-owner",
                "upload_session_id": "session-owner",
                "manifest_upload_url": "https://uploads.example.invalid/manifest"
            })
            .to_string(),
        )
        .expect_at_least(1)
        .create();

    let retry_save_mock = server
        .mock("POST", format!("{workspace_path}/caches").as_str())
        .match_header("authorization", "Bearer test-save-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "main",
                "cache_entry_id": "entry-final",
                "exists": true,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": 18,
                "cas_layout": "file-v1"
            })
            .to_string(),
        )
        .expect(1)
        .create();

    let stage_mock = server
        .mock(
            "POST",
            format!("{workspace_path}/caches/blobs/stage").as_str(),
        )
        .match_header("authorization", "Bearer test-save-token")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({"upload_urls": [], "already_present": []}).to_string())
        .expect(1)
        .create();

    let alias_pointer_mock = server
        .mock("GET", alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-save-token")
        .with_status(404)
        .expect(1)
        .create();
    let alias_publish_mock = server
        .mock("PUT", alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-save-token")
        .match_header("if-match", "0")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-final",
            "publish_mode": "cas",
            "write_scope_tag": "main"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "1",
                "cache_entry_id": "entry-final",
                "status": "ready"
            })
            .to_string(),
        )
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
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "Expected proxy run to retry upload-in-progress contention and publish, stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        combined.contains("KV batch flush: skipped"),
        "Expected contention retry log, got: {combined}"
    );

    contended_save_mock.assert();
    retry_save_mock.assert();
    stage_mock.assert();
    alias_pointer_mock.assert();
    alias_publish_mock.assert();
}

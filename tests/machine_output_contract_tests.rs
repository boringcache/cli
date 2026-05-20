use mockito::Matcher;
use serde_json::Value;
use serde_json::json;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const DUMMY_API_URL: &str = "http://127.0.0.1:65535";
const CI_RUN_ENV_VARS: &[&str] = &[
    "BORINGCACHE_CI_PROVIDER",
    "BORINGCACHE_CI_RUN_ID",
    "BORINGCACHE_CI_RUN_ATTEMPT",
    "BORINGCACHE_CI_REPOSITORY",
    "BORINGCACHE_CI_REF",
    "BORINGCACHE_CI_REF_NAME",
    "BORINGCACHE_CI_REF_TYPE",
    "BORINGCACHE_CI_HEAD_REF",
    "BORINGCACHE_CI_BASE_REF",
    "BORINGCACHE_CI_DEFAULT_BRANCH",
    "BORINGCACHE_CI_PR_NUMBER",
    "BORINGCACHE_CI_SHA",
    "BORINGCACHE_CI_RUN_STARTED_AT",
    "BORINGCACHE_BENCHMARK_MODE",
    "GITHUB_ACTIONS",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "GITHUB_DEFAULT_BRANCH",
    "GITHUB_EVENT_PATH",
    "GITHUB_SHA",
];

struct Placeholder {
    value: String,
    placeholder: &'static str,
}

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

fn apply_test_env(cmd: &mut Command) -> &mut Command {
    cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN")
        .env_remove("BORINGCACHE_ADMIN_TOKEN")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .env_remove("CARGO_INCREMENTAL")
        .env_remove("CC")
        .env_remove("CXX");
    for name in CI_RUN_ENV_VARS {
        cmd.env_remove(name);
    }
    cmd
}

fn mocked_api_command(temp_dir: &TempDir, api_url: &str) -> Command {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    command
        .current_dir(temp_dir.path())
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", api_url);
    command
}

fn path_placeholder(path: &Path, placeholder: &'static str) -> Placeholder {
    Placeholder {
        value: path.to_string_lossy().into_owned(),
        placeholder,
    }
}

fn home_placeholder() -> Placeholder {
    let home = dirs::home_dir().expect("home dir");
    path_placeholder(&home, "$HOME")
}

fn workspace_root_placeholders(path: &Path) -> Vec<Placeholder> {
    let mut placeholders = Vec::new();
    if let Ok(canonical) = std::fs::canonicalize(path) {
        placeholders.push(path_placeholder(&canonical, "$WORKSPACE_ROOT"));
    }
    placeholders.push(path_placeholder(path, "$WORKSPACE_ROOT"));
    placeholders
}

fn assert_machine_output_matches_fixture(actual_stdout: &[u8], fixture: &str) {
    assert_machine_output_matches_fixture_with_placeholders(actual_stdout, fixture, &[]);
}

fn assert_machine_output_matches_fixture_with_placeholders(
    actual_stdout: &[u8],
    fixture: &str,
    placeholders: &[Placeholder],
) {
    let actual: Value = serde_json::from_slice(actual_stdout).expect("actual CLI JSON");
    let expected: Value = serde_json::from_str(fixture).expect("fixture JSON");
    let actual = normalize_machine_output(actual, placeholders);

    assert_eq!(
        actual, expected,
        "CLI machine output drifted. Review the consumer impact before updating this fixture."
    );
}

fn normalize_machine_output(mut value: Value, placeholders: &[Placeholder]) -> Value {
    match &mut value {
        Value::String(string) => {
            for placeholder in placeholders {
                if !placeholder.value.is_empty() {
                    *string = string.replace(&placeholder.value, placeholder.placeholder);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    value
}

fn normalize_machine_output_in_place(value: &mut Value, placeholders: &[Placeholder]) {
    match value {
        Value::String(string) => {
            for placeholder in placeholders {
                if !placeholder.value.is_empty() {
                    *string = string.replace(&placeholder.value, placeholder.placeholder);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[test]
fn run_dry_run_manual_archive_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "test-org/test-workspace",
            "custom-tag:/tmp/custom-path",
            "--dry-run",
            "--json",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("run dry-run json");

    assert!(
        output.status.success(),
        "dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/run_dry_run_manual_archive_v1.json"),
    );
}

#[test]
fn docker_dry_run_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "docker",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "docker-cache",
            "--no-platform",
            "--no-git",
            "--dry-run",
            "--json",
            "--",
            "docker",
            "buildx",
            "build",
            ".",
        ])
        .output()
        .expect("docker dry-run json");

    assert!(
        output.status.success(),
        "docker dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/docker_dry_run_v1.json"),
    );
}

#[test]
fn bazel_setup_plan_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .env("BORINGCACHE_BAZEL_STABLE_HOST_ENV", "0")
        .args([
            "bazel",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "bazel-cache",
            "--endpoint-host",
            "host.docker.internal",
            "--port",
            "6001",
            "--no-platform",
            "--no-git",
            "--dry-run",
            "--json",
            "--",
            "bazel",
            "build",
            "//...",
        ])
        .output()
        .expect("bazel dry-run json");

    assert!(
        output.status.success(),
        "bazel dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture_with_placeholders(
        &output.stdout,
        include_str!("fixtures/machine-output/bazel_setup_plan_v1.json"),
        &[home_placeholder()],
    );
}

#[test]
fn gradle_setup_plan_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "gradle",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "gradle-cache",
            "--endpoint-host",
            "host.docker.internal",
            "--port",
            "6001",
            "--no-platform",
            "--no-git",
            "--read-only",
            "--dry-run",
            "--json",
            "--",
            "./gradlew",
            "build",
            "--no-daemon",
        ])
        .output()
        .expect("gradle dry-run json");

    assert!(
        output.status.success(),
        "gradle dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture_with_placeholders(
        &output.stdout,
        include_str!("fixtures/machine-output/gradle_setup_plan_v1.json"),
        &[home_placeholder()],
    );
}

#[test]
fn maven_setup_plan_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "maven",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "maven-cache",
            "--endpoint-host",
            "host.docker.internal",
            "--port",
            "6001",
            "--no-platform",
            "--no-git",
            "--read-only",
            "--dry-run",
            "--json",
            "--",
            "mvn",
            "install",
            "-DskipTests",
        ])
        .output()
        .expect("maven dry-run json");

    assert!(
        output.status.success(),
        "maven dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut placeholders = workspace_root_placeholders(temp_dir.path());
    placeholders.push(home_placeholder());
    assert_machine_output_matches_fixture_with_placeholders(
        &output.stdout,
        include_str!("fixtures/machine-output/maven_setup_plan_v1.json"),
        &placeholders,
    );
}

#[tokio::test]
async fn check_json_matches_v1_contract() {
    let mut server = mockito::Server::new_async().await;
    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/test/workspace/caches\?entries=deps$".to_string()),
        )
        .match_header("authorization", "Bearer restore-token-fixture")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "deps",
                "status": "hit",
                "cache_entry_id": "entry-123",
                "manifest_root_digest": "sha256:root",
                "size": 1024,
                "compressed_size": 512
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("temp dir");
    let output = mocked_api_command(&temp_dir, &server.url())
        .env("BORINGCACHE_RESTORE_TOKEN", "restore-token-fixture")
        .args([
            "check",
            "test/workspace",
            "deps",
            "--json",
            "--no-platform",
            "--no-git",
        ])
        .output()
        .expect("check json");

    assert!(
        output.status.success(),
        "check should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    restore_mock.assert_async().await;
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/check_hit_v1.json"),
    );
}

#[tokio::test]
async fn status_json_matches_v1_contract() {
    let mut server = mockito::Server::new_async().await;
    let status_mock = server
        .mock(
            "GET",
            Matcher::Regex(
                r"^/v2/workspaces/test/workspace/status\?period=7d&limit=1$".to_string(),
            ),
        )
        .match_header("authorization", "Bearer restore-token-fixture")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(status_response_body().to_string())
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("temp dir");
    let output = mocked_api_command(&temp_dir, &server.url())
        .env("BORINGCACHE_RESTORE_TOKEN", "restore-token-fixture")
        .args([
            "status",
            "test/workspace",
            "--period",
            "7d",
            "--limit",
            "1",
            "--json",
        ])
        .output()
        .expect("status json");

    assert!(
        output.status.success(),
        "status should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    status_mock.assert_async().await;
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/status_workspace_v1.json"),
    );
}

#[tokio::test]
async fn token_list_json_matches_v1_contract() {
    let mut server = mockito::Server::new_async().await;
    let token_mock = server
        .mock(
            "GET",
            Matcher::Regex(
                r"^/v2/workspaces/test/workspace/tokens\?limit=20&offset=0$".to_string(),
            ),
        )
        .match_header("authorization", "Bearer admin-token-fixture")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "workspace": {
                    "name": "testing",
                    "slug": "test/workspace"
                },
                "filter": {
                    "include_inactive": false
                },
                "pagination": {
                    "limit": 20,
                    "offset": 0,
                    "total": 1,
                    "returned": 1,
                    "has_more": false
                },
                "tokens": [{
                    "id": "tok_restore_1",
                    "name": "CI restore",
                    "access_level": "restore",
                    "scope_type": "workspace",
                    "state": "active",
                    "active": true,
                    "created_at": "2026-04-15T00:00:00Z",
                    "expires_at": null,
                    "expires_in_days": null,
                    "last_used_at": null,
                    "write_tag_prefixes": []
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let temp_dir = TempDir::new().expect("temp dir");
    let output = mocked_api_command(&temp_dir, &server.url())
        .env("BORINGCACHE_ADMIN_TOKEN", "admin-token-fixture")
        .args(["token", "list", "test/workspace", "--json"])
        .output()
        .expect("token list json");

    assert!(
        output.status.success(),
        "token list should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    token_mock.assert_async().await;
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/token_list_v1.json"),
    );
}

fn status_response_body() -> Value {
    json!({
        "workspace": {
            "id": "ws_1",
            "name": "Demo",
            "slug": "test/workspace",
            "description": "workspace",
            "provisioned": true,
            "created_at": "2026-04-15T00:00:00Z",
            "updated_at": "2026-04-15T00:00:00Z"
        },
        "period": {
            "key": "7d",
            "started_at": "2026-04-08T00:00:00Z",
            "ended_at": "2026-04-15T00:00:00Z"
        },
        "generated_at": "2026-04-15T00:00:00Z",
        "inventory": {
            "tagged_entries_count": 4,
            "tagged_storage_bytes": 1024,
            "tagged_hits": 10,
            "version_count": 2,
            "orphaned_entries_count": 0,
            "orphaned_storage_bytes": 0,
            "dedup_unique_bytes": 800,
            "dedup_logical_bytes": 1200,
            "dedup_savings_bytes": 400,
            "dedup_ratio": 0.33
        },
        "operations": {
            "cache": {
                "total_requests": 12,
                "total_hits": 9,
                "lookup_requests": 12,
                "hit_rate": 0.75,
                "bytes_total": 4096,
                "avg_latency_ms": 12.5,
                "degraded_count": 0
            },
            "runtime": {
                "total_queries": 12,
                "error_count": 0,
                "error_rate": 0.0,
                "avg_latency_ms": 10.0,
                "degraded_count": 0
            },
            "cache_health": {
                "warm_hit_rate": 0.9,
                "cold_misses": 1,
                "recurring_misses": 2,
                "cold_pct": 0.33,
                "recurring_pct": 0.67,
                "session_miss_total": 3,
                "normal_misses": 3,
                "degraded_misses": 0,
                "total_misses": 3,
                "degraded_pct": 0.0,
                "excluded_seed_misses": 0,
                "excluded_seed_sessions": 0
            },
            "session_health": {
                "total_sessions": 1,
                "healthy_sessions": 1,
                "error_sessions": 0,
                "degraded_sessions": 0,
                "avg_hit_rate": 0.75,
                "avg_duration_ms": 4000.0
            }
        },
        "savings": {
            "cache_hits": 9,
            "bytes_served": 2048,
            "bytes_written": 1024,
            "cli_restores": 2,
            "cli_restore_bytes": 2048,
            "cli_compression_saved": 512,
            "cli_avg_restore_ms": 120.0,
            "dedup_unique_bytes": 800,
            "dedup_logical_bytes": 1200,
            "dedup_savings_bytes": 400,
            "dedup_ratio": 0.33
        },
        "tools": [{
            "tool": "turbo",
            "total": 12,
            "hits": 9,
            "misses": 3,
            "lookup_total": 12,
            "hit_rate": 0.75,
            "warm_hit_rate": 0.9,
            "recurring_misses": 2,
            "new_key_misses": 1,
            "bytes_total": 2048,
            "avg_latency_ms": 12.5,
            "degraded": 0
        }],
        "sessions": [{
            "session_id": "sess_1",
            "tool": "turbo",
            "project_hint": "demo",
            "phase_hint": "build",
            "run_uid": null,
            "run_label": "local/abc12345",
            "run_identity": {},
            "summary_schema": "cache_session_summary.v2",
            "metadata_hints": {
                "lane": "ci"
            },
            "tool_stats": [
                {
                    "label": "Cache writes",
                    "value": "2"
                },
                {
                    "label": "Read bytes",
                    "value": "1 KB"
                }
            ],
            "hit_rate": 0.75,
            "hit_count": 9,
            "miss_count": 3,
            "error_count": 0,
            "error_details": [{
                "operation": "get",
                "count": 0
            }],
            "duration_seconds": 4.0,
            "bytes_read": 1024,
            "bytes_written": 512,
            "created_at": "2026-04-15T00:00:00Z",
            "missed_keys": [{
                "key_hash": "abc123",
                "miss_count": 3,
                "sampled_key_prefix": "deps-"
            }],
            "review": null
        }],
        "missed_keys": [{
            "key_hash": "abc123",
            "tool": "turbo",
            "miss_count": 3,
            "last_seen_at": "2026-04-15T00:00:00Z",
            "sampled_key_prefix": "deps-",
            "miss_state": "recurring"
        }]
    })
}

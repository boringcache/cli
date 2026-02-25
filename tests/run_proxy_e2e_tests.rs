#![cfg(unix)]

use std::env;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const DUMMY_API_URL: &str = "http://127.0.0.1:65535";

fn cli_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_boringcache")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap().join("target/debug/boringcache"))
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

#[test]
fn test_run_proxy_injects_env_and_substitutes_placeholders() {
    let temp_dir = TempDir::new().expect("temp dir");
    let port = free_port().to_string();
    let script = r#"expected_endpoint="http://127.0.0.1:$1"
expected_ref="127.0.0.1:$1/cache:main"
[ "${NX_SELF_HOSTED_REMOTE_CACHE_SERVER:-}" = "$expected_endpoint" ] || exit 2
[ "${TURBO_API:-}" = "$expected_endpoint" ] || exit 3
[ "${2:-}" = "$expected_ref" ] || exit 4
curl -fsS --max-time 2 "$expected_endpoint/v2/" >/dev/null || exit 5
"#;

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
            &port,
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
    let port = free_port().to_string();
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
            &port,
            "--",
            "sh",
            "-c",
            "exit 19",
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
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
    let port = free_port().to_string();
    let script = r#"expected_endpoint="http://127.0.0.1:$1"
[ "${NX_SELF_HOSTED_REMOTE_CACHE_SERVER:-}" = "$expected_endpoint" ] || exit 2
curl -fsS --max-time 2 "$expected_endpoint/v2/" >/dev/null || exit 3
"#;

    let pair = format!("deps:{}", cache_dir.display());
    let output = Command::new(cli_binary())
        .args([
            "run",
            "test-org/test-workspace",
            &pair,
            "--proxy",
            "main",
            "--skip-restore",
            "--skip-save",
            "--no-platform",
            "--no-git",
            "--host",
            "127.0.0.1",
            "--port",
            &port,
            "--",
            "sh",
            "-ec",
            script,
            "_",
            "{PORT}",
        ])
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
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

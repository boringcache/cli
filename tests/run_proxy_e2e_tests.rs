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

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[test]
fn test_run_proxy_injects_env_and_substitutes_placeholders() {
    if !python3_available() {
        eprintln!(
            "skipping test_run_proxy_injects_env_and_substitutes_placeholders: python3 missing"
        );
        return;
    }

    let temp_dir = TempDir::new().expect("temp dir");
    let port = free_port().to_string();
    let script = r#"import os, sys, urllib.request
expected_endpoint = f"http://127.0.0.1:{sys.argv[1]}"
if os.environ.get("NX_SELF_HOSTED_REMOTE_CACHE_SERVER") != expected_endpoint:
    raise SystemExit(2)
if os.environ.get("TURBO_API") != expected_endpoint:
    raise SystemExit(3)
expected_ref = f"127.0.0.1:{sys.argv[1]}/cache:main"
if sys.argv[2] != expected_ref:
    raise SystemExit(4)
with urllib.request.urlopen(expected_endpoint + "/v2/") as response:
    if response.status != 200:
        raise SystemExit(5)
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
            "python3",
            "-c",
            script,
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
    if !python3_available() {
        eprintln!(
            "skipping test_run_combined_archive_and_proxy_mode_executes_child: python3 missing"
        );
        return;
    }

    let temp_dir = TempDir::new().expect("temp dir");
    let cache_dir = temp_dir.path().join("cache");
    std::fs::create_dir_all(&cache_dir).expect("create cache dir");
    let port = free_port().to_string();
    let script = r#"import os, sys, urllib.request
expected_endpoint = f"http://127.0.0.1:{sys.argv[1]}"
if os.environ.get("NX_SELF_HOSTED_REMOTE_CACHE_SERVER") != expected_endpoint:
    raise SystemExit(2)
with urllib.request.urlopen(expected_endpoint + "/v2/") as response:
    if response.status != 200:
        raise SystemExit(3)
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
            "python3",
            "-c",
            script,
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

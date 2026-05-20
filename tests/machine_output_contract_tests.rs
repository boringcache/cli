use serde_json::Value;
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

fn apply_test_env(cmd: &mut Command) -> &mut Command {
    cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN")
        .env_remove("GITHUB_ACTIONS")
}

fn assert_machine_output_matches_fixture(actual_stdout: &[u8], fixture: &str) {
    let actual: Value = serde_json::from_slice(actual_stdout).expect("actual CLI JSON");
    let expected: Value = serde_json::from_str(fixture).expect("fixture JSON");

    assert_eq!(
        actual, expected,
        "CLI machine output drifted. Review the consumer impact before updating this fixture."
    );
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

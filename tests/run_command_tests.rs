use std::env;
use std::path::PathBuf;
use std::process::Command;

const DUMMY_API_URL: &str = "http://127.0.0.1:65535";

fn cli_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_boringcache")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap().join("target/debug/boringcache"))
}

fn apply_test_env(cmd: &mut Command) -> &mut Command {
    if std::env::var("BORINGCACHE_API_URL").is_err() {
        cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL);
    }
    cmd.env("BORINGCACHE_TEST_MODE", "1");
    cmd
}

#[test]
fn test_run_propagates_child_exit_code() {
    let child = cli_binary();
    let child = child.to_str().expect("CLI path must be valid UTF-8");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "test-tag:/tmp/test",
            "--skip-restore",
            "--skip-save",
            "--",
            child,
            "invalid-command",
        ])
        .output()
        .expect("Failed to execute run command");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected child exit code 1, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_run_returns_127_for_missing_command() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "test-tag:/tmp/test",
            "--skip-restore",
            "--skip-save",
            "--",
            "boringcache-command-does-not-exist",
        ])
        .output()
        .expect("Failed to execute run command");

    assert_eq!(
        output.status.code(),
        Some(127),
        "Expected exit code 127, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Command not found"),
        "Expected not found error message, got: {}",
        stderr
    );
}

#[test]
fn test_run_dry_run_prints_restore_and_save() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "test-tag:/tmp/test",
            "--dry-run",
            "--",
            "boringcache-command-does-not-exist",
        ])
        .output()
        .expect("Failed to execute run dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("boringcache restore"));
    assert!(stdout.contains("boringcache save"));
}

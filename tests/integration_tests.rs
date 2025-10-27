use std::env;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn cli_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_boringcache")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap().join("target/debug/boringcache"))
}
const DUMMY_API_URL: &str = "http://127.0.0.1:65535";

fn apply_test_env(cmd: &mut Command) -> &mut Command {
    if std::env::var("BORINGCACHE_API_URL").is_err() {
        cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL);
    }
    cmd.env("BORINGCACHE_TEST_MODE", "1");
    cmd
}

fn run_cli_command(args: &[&str]) -> std::process::Output {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    command
        .args(args)
        .output()
        .expect("Failed to execute CLI command")
}

fn run_cli_command_isolated(args: &[&str]) -> std::process::Output {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    command
        .args(args)
        .env("HOME", temp_dir.path())
        .env_remove("BORINGCACHE_TOKEN")
        .output()
        .expect("Failed to execute CLI command")
}

#[test]
fn test_cli_help() {
    let output = run_cli_command(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("High-performance cache management CLI"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("auth"));
    assert!(stdout.contains("save"));
    assert!(stdout.contains("restore"));
    assert!(stdout.contains("workspaces"));
}

#[test]
fn test_cli_version() {
    let output = run_cli_command(&["--version"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("boringcache"));
    assert!(stdout.contains("0.1.0"));
}

#[test]
fn test_auth_command_missing_token() {
    let output = run_cli_command(&["auth"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("token") || stderr.contains("required"));
}

#[test]
fn test_auth_command_help() {
    let output = run_cli_command(&["auth", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--token"));
    assert!(stdout.contains("Usage: boringcache auth"));
}

#[test]
fn test_save_command_missing_args() {
    let output = run_cli_command(&["save"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should require workspace, paths, and key
    assert!(stderr.contains("required") || stderr.contains("argument"));
}

#[test]
fn test_save_command_help() {
    let output = run_cli_command(&["save", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache save"));
    assert!(stdout.contains("PATH_TAG_PAIRS") || stdout.contains("tag:path"));
}

#[test]
fn test_restore_command_missing_args() {
    let output = run_cli_command(&["restore"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required")
            || stderr.contains("argument")
            || stderr.contains("must be provided")
    );
}

#[test]
fn test_restore_command_help() {
    let output = run_cli_command(&["restore", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache restore"));
    assert!(stdout.contains("TAG_PATH_PAIRS") || stdout.contains("tag:path"));
}

#[test]
fn test_workspaces_command_help() {
    let output = run_cli_command(&["workspaces", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache workspaces"));
}

#[test]
fn test_verbose_flag() {
    let output = run_cli_command(&["--verbose", "workspaces", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache workspaces"));
}

#[test]
fn test_invalid_command() {
    let output = run_cli_command(&["invalid-command"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error") || stderr.contains("invalid"));
}

#[test]
fn test_workspaces_command_without_auth() {
    let output = run_cli_command_isolated(&["workspaces"]);

    // Either succeeds with valid cached auth or fails with auth/network error
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // If successful, should show workspace list or empty result
        assert!(stdout.contains("workspaces") || stdout.contains("Total:") || stdout.is_empty());
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let error_messages_found = stderr.contains("auth")
            || stderr.contains("token")
            || stderr.contains("connection")
            || stderr.contains("401")
            || stderr.contains("unauthorized")
            || stderr.contains("dns error")
            || stderr.contains("Failed to send")
            || stderr.contains("No configuration found")
            || stderr.contains("API Error")
            || stdout.contains("error");

        if !error_messages_found {
            eprintln!("Test failed - Expected auth/network error but got:");
            eprintln!("Exit code: {:?}", output.status.code());
            eprintln!("STDOUT: {}", stdout);
            eprintln!("STDERR: {}", stderr);
        }
        assert!(
            error_messages_found,
            "Expected auth/network error but got different error"
        );
    }
}

// Test environment variable handling
#[test]
fn test_api_url_env_var() {
    use std::env;

    // Set custom API URL
    env::set_var("BORINGCACHE_API_URL", "https://custom.api.com/v1");

    let output = run_cli_command(&["workspaces"]);

    // Should still fail with auth but might show different error indicating custom URL was used
    assert!(!output.status.success());

    // Clean up
    env::remove_var("BORINGCACHE_API_URL");
}

#[test]
fn test_restore_fail_on_cache_miss_flag_help() {
    let output = run_cli_command(&["restore", "--help"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--fail-on-cache-miss"));
    assert!(stdout.contains("Fail the workflow if cache entry is not found"));
}

#[test]
fn test_restore_lookup_only_flag_help() {
    let output = run_cli_command(&["restore", "--help"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--lookup-only"));
    assert!(stdout.contains("Check if a cache entry exists without downloading"));
}

#[test]
fn test_restore_new_flags_require_auth() {
    // Test that the new flags still require auth like other restore operations
    let output = run_cli_command_isolated(&[
        "restore",
        "test/workspace",
        "some-cache",
        "--fail-on-cache-miss",
    ]);

    // Should fail due to missing auth, not due to flag parsing
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should contain auth-related error, not argument parsing error
    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_restore_lookup_only_requires_auth() {
    // Test that lookup-only flag still requires auth
    let output =
        run_cli_command_isolated(&["restore", "test/workspace", "some-cache", "--lookup-only"]);

    // Should fail due to missing auth, not due to flag parsing
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should contain auth-related error, not argument parsing error
    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_restore_flags_can_be_combined() {
    // Test that flags can be used together (though this combination might not be very useful)
    let output = run_cli_command_isolated(&[
        "restore",
        "test/workspace",
        "some-cache",
        "--fail-on-cache-miss",
        "--lookup-only",
    ]);

    // Should fail due to missing auth, not due to flag parsing
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should contain auth-related error, not argument parsing error
    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_save_single_file_path_resolution() {
    use std::fs;

    // Test that saving a single file (not a directory) works correctly
    // This tests the bug fix for path joining when base_path is a file
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create a single test file
    let test_file = temp_dir.path().join("test-binary");
    fs::write(&test_file, b"test content for single file").expect("Failed to write test file");

    let output = run_cli_command_isolated(&[
        "save",
        "test/workspace",
        &format!("single-file-tag:{}", test_file.display()),
    ]);

    // Without auth, should fail with auth error, not path resolution error
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    // Should NOT contain path-related errors like "No such file or directory"
    // or "Failed to open file"
    assert!(
        !combined.contains("No such file or directory"),
        "Should not have path resolution errors. Output: {}",
        combined
    );
    assert!(
        !combined.contains("Failed to open file"),
        "Should not have file open errors. Output: {}",
        combined
    );

    // Should fail due to missing auth (expected behavior without proper setup)
    assert!(
        combined.contains("auth") || combined.contains("token") || combined.contains("config"),
        "Should fail with auth error. Output: {}",
        combined
    );
}

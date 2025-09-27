use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const CLI_BINARY: &str = "./target/debug/boringcache";

fn run_cli_command(args: &[&str]) -> std::process::Output {
    Command::new(CLI_BINARY)
        .args(args)
        .output()
        .expect("Failed to execute CLI command")
}

fn run_cli_command_isolated(args: &[&str]) -> std::process::Output {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    Command::new(CLI_BINARY)
        .args(args)
        .env("HOME", temp_dir.path())
        .env_remove("BORINGCACHE_API_URL")
        .env_remove("BORINGCACHE_TOKEN")
        .output()
        .expect("Failed to execute CLI command")
}

fn run_cli_command_in_dir(args: &[&str], dir: &Path) -> std::process::Output {
    // Use absolute path to CLI binary since we're changing directories
    let cli_path = std::env::current_dir()
        .unwrap()
        .join("target/debug/boringcache");
    Command::new(cli_path)
        .args(args)
        .current_dir(dir)
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
    assert!(stdout.contains("0.4.0"));
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

// Test save/restore workflow with temporary directories
#[test]
fn test_save_restore_workflow_missing_auth() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache");
    fs::create_dir(&cache_path).expect("Failed to create cache dir");

    // Create test file
    let test_file = cache_path.join("test.txt");
    fs::write(&test_file, "test content").expect("Failed to write test file");

    // Try to save without authentication - should fail with auth error
    let output = run_cli_command_in_dir(
        &[
            "save",
            "test-org/test-workspace",
            &format!("test-key:{}", cache_path.to_str().unwrap()),
        ],
        temp_dir.path(),
    );

    // Should fail due to missing auth
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Could fail with auth error, network error, or filesystem error depending on implementation
    assert!(
        stderr.contains("auth")
            || stderr.contains("token")
            || stderr.contains("connection")
            || stderr.contains("401")
            || stderr.contains("unauthorized")
            || stderr.contains("dns error")
            || stderr.contains("Failed to send")
            || stderr.contains("File exists")
            || stderr.contains("Error:")
    );
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
fn test_save_with_multiple_paths() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create multiple test directories/files
    let cache_path1 = temp_dir.path().join("cache1");
    let cache_path2 = temp_dir.path().join("cache2");
    fs::create_dir(&cache_path1).expect("Failed to create cache dir 1");
    fs::create_dir(&cache_path2).expect("Failed to create cache dir 2");

    fs::write(cache_path1.join("file1.txt"), "content1").expect("Failed to write file1");
    fs::write(cache_path2.join("file2.txt"), "content2").expect("Failed to write file2");

    let output = run_cli_command_in_dir(
        &[
            "save",
            "test-org/test-workspace",
            &format!(
                "key1:{},key2:{}",
                cache_path1.to_str().unwrap(),
                cache_path2.to_str().unwrap()
            ),
        ],
        temp_dir.path(),
    );

    // Should fail due to auth but the command structure should be valid
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should not fail due to argument parsing, only auth/network/filesystem errors
    assert!(
        stderr.contains("auth")
            || stderr.contains("token")
            || stderr.contains("connection")
            || stderr.contains("401")
            || stderr.contains("unauthorized")
            || stderr.contains("dns error")
            || stderr.contains("Failed to send")
            || stderr.contains("File exists")
            || stderr.contains("Error:")
    );
}

#[test]
fn test_restore_with_target_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let target_path = temp_dir.path().join("restore_target");

    let output = run_cli_command_in_dir(
        &[
            "restore",
            "test-workspace",
            &format!("test-restore-key:{}", target_path.to_str().unwrap()),
        ],
        temp_dir.path(),
    );

    // Should fail due to auth but command structure should be valid
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("auth")
            || stderr.contains("token")
            || stderr.contains("connection")
            || stderr.contains("401")
            || stderr.contains("unauthorized")
            || stderr.contains("dns error")
            || stderr.contains("Failed to send")
            || stderr.contains("Error:")
    );
}

#[test]
fn test_restore_without_target_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let output = run_cli_command_in_dir(
        &["restore", "test-workspace", "test-restore-key"],
        temp_dir.path(),
    );

    // Should fail due to auth but command structure should be valid
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("auth")
            || stderr.contains("token")
            || stderr.contains("connection")
            || stderr.contains("401")
            || stderr.contains("unauthorized")
            || stderr.contains("dns error")
            || stderr.contains("Failed to send")
            || stderr.contains("Error:")
    );
}

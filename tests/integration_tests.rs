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
        .env_remove("BORINGCACHE_API_TOKEN")
        .output()
        .expect("Failed to execute CLI command")
}

fn run_cli_command_with_temp(args: &[&str], temp_dir: &TempDir) -> std::process::Output {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    command
        .args(args)
        .env("HOME", temp_dir.path())
        .env_remove("BORINGCACHE_TOKEN")
        .env_remove("BORINGCACHE_API_TOKEN")
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
    assert!(stdout.contains("mount"));
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

    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
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
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("Output in JSON format"));
}

#[test]
fn test_ls_command_json_flag_help() {
    let output = run_cli_command(&["ls", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("Output in JSON format"));
}

#[test]
fn test_config_get_json_flag_help() {
    let output = run_cli_command(&["config", "get", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("Output in JSON format"));
}

#[test]
fn test_config_list_json_flag_help() {
    let output = run_cli_command(&["config", "list", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json"));
    assert!(stdout.contains("Output in JSON format"));
}

#[test]
fn test_docker_registry_alias_help() {
    let output = run_cli_command(&["docker-registry", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache docker-registry"));
    assert!(stdout.contains("cache registry proxy"));
    assert!(stdout.contains("--fail-on-cache-error"));
}

#[test]
fn test_serve_compat_alias_help() {
    let output = run_cli_command(&["serve", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache docker-registry"));
    assert!(stdout.contains("cache registry proxy"));
    assert!(stdout.contains("--fail-on-cache-error"));
}

#[test]
fn test_cache_registry_alias_help() {
    let output = run_cli_command(&["cache-registry", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache docker-registry"));
    assert!(stdout.contains("cache registry proxy"));
    assert!(stdout.contains("--fail-on-cache-error"));
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

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);

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

#[test]
fn test_api_url_env_var() {
    use std::env;

    env::set_var("BORINGCACHE_API_URL", "https://custom.api.com");

    let output = run_cli_command(&["workspaces"]);

    assert!(!output.status.success());

    env::remove_var("BORINGCACHE_API_URL");
}

#[test]
fn test_restore_fail_on_cache_miss_flag_help() {
    let output = run_cli_command(&["restore", "--help"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--fail-on-cache-miss"));
    assert!(stdout.contains("Exit with error if cache entry is not found"));
}

#[test]
fn test_restore_fail_on_cache_error_flag_help() {
    let output = run_cli_command(&["restore", "--help"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--fail-on-cache-error"));
    assert!(stdout.contains("Exit with error if restore encounters cache/backend failures"));
}

#[test]
fn test_save_fail_on_cache_error_flag_help() {
    let output = run_cli_command(&["save", "--help"]);
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--fail-on-cache-error"));
    assert!(stdout.contains("Exit with error if save encounters cache/backend failures"));
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
    let output = run_cli_command_isolated(&[
        "restore",
        "test/workspace",
        "some-cache",
        "--fail-on-cache-miss",
    ]);

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_restore_lookup_only_requires_auth() {
    let output =
        run_cli_command_isolated(&["restore", "test/workspace", "some-cache", "--lookup-only"]);

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_restore_flags_can_be_combined() {
    let output = run_cli_command_isolated(&[
        "restore",
        "test/workspace",
        "some-cache",
        "--fail-on-cache-miss",
        "--lookup-only",
    ]);

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_restore_fail_on_cache_error_requires_auth() {
    let output = run_cli_command_isolated(&[
        "restore",
        "test/workspace",
        "some-cache",
        "--fail-on-cache-error",
    ]);

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_save_fail_on_cache_error_requires_auth() {
    use std::fs;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let payload_path = temp_dir.path().join("payload.txt");
    fs::write(&payload_path, b"test").expect("Failed to write payload");

    let output = run_cli_command_isolated(&[
        "save",
        "test/workspace",
        &format!("cache-key:{}", payload_path.display()),
        "--fail-on-cache-error",
    ]);

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("auth") || stderr.contains("token") || stderr.contains("config"));
}

#[test]
fn test_save_single_file_path_resolution() {
    use std::fs;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let test_file = temp_dir.path().join("test-binary");
    fs::write(&test_file, b"test content for single file").expect("Failed to write test file");

    let output = run_cli_command_isolated(&[
        "save",
        "test/workspace",
        &format!("single-file-tag:{}", test_file.display()),
    ]);

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

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

    assert!(
        combined.contains("auth") || combined.contains("token") || combined.contains("config"),
        "Should fail with auth error. Output: {}",
        combined
    );
}

#[test]
fn test_mount_command_help() {
    let output = run_cli_command(&["mount", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: boringcache mount"));
    assert!(stdout.contains("WORKSPACE"));
    assert!(stdout.contains("TAG_PATH"));
    assert!(stdout.contains("--verbose"));
}

#[test]
fn test_mount_command_missing_args() {
    let output = run_cli_command(&["mount"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("argument"),
        "Expected missing argument error. Got: {}",
        stderr
    );
}

#[test]
fn test_mount_command_missing_tag_path() {
    let output = run_cli_command(&["mount", "test/workspace"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("argument"),
        "Expected missing argument error. Got: {}",
        stderr
    );
}

#[test]
fn test_mount_command_invalid_tag_path_format() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output =
        run_cli_command_with_temp(&["mount", "test/workspace", "invalid-no-colon"], &temp_dir);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("Invalid tag:path format")
            || combined.contains("auth")
            || combined.contains("token")
            || combined.contains("config"),
        "Expected format or auth error. Got: {}",
        combined
    );
}

#[test]
fn test_mount_command_requires_auth() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache_dir = temp_dir.path().join("test-cache");
    std::fs::create_dir(&cache_dir).expect("Failed to create cache dir");

    let tag_path = format!("my-cache:{}", cache_dir.display());
    let output = run_cli_command_with_temp(&["mount", "test/workspace", &tag_path], &temp_dir);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("auth")
            || combined.contains("token")
            || combined.contains("config")
            || combined.contains("No configuration found"),
        "Expected auth error. Got: {}",
        combined
    );
}

#[test]
fn test_mount_command_verbose_flag() {
    let output = run_cli_command(&["mount", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-v"));
    assert!(stdout.contains("--verbose"));
    assert!(stdout.contains("Enable verbose output"));
}

#[test]
fn test_mount_command_validates_workspace_format() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output =
        run_cli_command_with_temp(&["mount", "invalid_workspace", "tag:./path"], &temp_dir);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    assert!(
        combined.contains("Invalid workspace")
            || combined.contains("format")
            || combined.contains("auth")
            || combined.contains("token")
            || combined.contains("config"),
        "Expected workspace format or auth error. Got: {}",
        combined
    );
}

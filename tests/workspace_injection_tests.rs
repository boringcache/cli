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
const TEST_WORKSPACE: &str = "test-org/test-project";

fn apply_test_env(cmd: &mut Command) -> &mut Command {
    if std::env::var("BORINGCACHE_API_URL").is_err() {
        cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL);
    }
    cmd.env("BORINGCACHE_TEST_MODE", "1");
    cmd
}

fn run_cli_with_default_workspace(args: &[&str]) -> std::process::Output {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    command
        .args(args)
        .env("HOME", temp_dir.path())
        .env("BORINGCACHE_DEFAULT_WORKSPACE", TEST_WORKSPACE)
        .env_remove("BORINGCACHE_TOKEN")
        .env_remove("BORINGCACHE_API_TOKEN")
        .output()
        .expect("Failed to execute CLI command")
}

fn run_cli_without_default_workspace(args: &[&str]) -> std::process::Output {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    command
        .args(args)
        .env("HOME", temp_dir.path())
        .env_remove("BORINGCACHE_TOKEN")
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_DEFAULT_WORKSPACE")
        .output()
        .expect("Failed to execute CLI command")
}

// Test that save works with default workspace and tag:path only
#[test]
fn test_save_with_default_workspace_and_tag_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_path, "test").expect("Failed to create test file");

    let arg = format!("test-tag:{}", test_path.display());
    let output = run_cli_with_default_workspace(&["save", &arg]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should get past argument parsing - will fail on auth or proceed with save
    assert!(
        !stderr.contains("required arguments were not provided")
            && !stderr.contains("<PATH_TAG_PAIRS>"),
        "Expected to pass argument parsing, got stderr: {}\nstdout: {}",
        stderr,
        stdout
    );
}

// Test that save works with default workspace, tag:path, and flags
#[test]
fn test_save_with_default_workspace_tag_path_and_flags() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_path, "test").expect("Failed to create test file");

    let arg = format!("test-tag:{}", test_path.display());
    let output = run_cli_with_default_workspace(&["save", &arg, "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required arguments were not provided")
            && !stderr.contains("<PATH_TAG_PAIRS>")
    );
}

// Test that save works with default workspace and multiple flags
#[test]
fn test_save_with_default_workspace_and_multiple_flags() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_path, "test").expect("Failed to create test file");

    let arg = format!("test-tag:{}", test_path.display());
    let output = run_cli_with_default_workspace(&["save", &arg, "--force", "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required arguments were not provided")
            && !stderr.contains("<PATH_TAG_PAIRS>")
    );
}

// Test that save with explicit workspace is not affected
#[test]
fn test_save_with_explicit_workspace() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_path, "test").expect("Failed to create test file");

    let arg = format!("test-tag:{}", test_path.display());
    let output = run_cli_with_default_workspace(&["save", "explicit/workspace", &arg, "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should pass argument parsing
    assert!(
        !stderr.contains("required arguments were not provided")
            && !stderr.contains("<PATH_TAG_PAIRS>")
    );
}

// Test that save without default workspace fails with proper error
#[test]
fn test_save_without_default_workspace() {
    let output = run_cli_without_default_workspace(&["save", "test-tag:/tmp/test"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should fail with missing argument error
    assert!(
        stderr.contains("required arguments were not provided")
            || stderr.contains("<PATH_TAG_PAIRS>"),
        "Expected argument parsing error, got: {}",
        stderr
    );
}

// Test restore with default workspace
#[test]
fn test_restore_with_default_workspace_and_tag_path() {
    let output = run_cli_with_default_workspace(&["restore", "test-tag:/tmp/test"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test restore with default workspace and flags
#[test]
fn test_restore_with_default_workspace_and_flags() {
    let output =
        run_cli_with_default_workspace(&["restore", "test-tag:/tmp/test", "--lookup-only", "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test restore with fail-on-cache-miss flag
#[test]
fn test_restore_with_default_workspace_and_fail_on_cache_miss() {
    let output =
        run_cli_with_default_workspace(&["restore", "test-tag:/tmp/test", "--fail-on-cache-miss"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test delete with default workspace
#[test]
fn test_delete_with_default_workspace() {
    let output = run_cli_with_default_workspace(&["delete", "test-tag"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test delete with default workspace and flags
#[test]
fn test_delete_with_default_workspace_and_flags() {
    let output = run_cli_with_default_workspace(&["delete", "test-tag", "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test ls with default workspace
#[test]
fn test_ls_with_default_workspace() {
    let output = run_cli_with_default_workspace(&["ls"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test ls with default workspace and flags
#[test]
fn test_ls_with_default_workspace_and_flags() {
    let output = run_cli_with_default_workspace(&["ls", "-v", "--limit", "10"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No workspace specified")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Expected auth/workspace error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test that explicit workspace in ls is not affected
#[test]
fn test_ls_with_explicit_workspace() {
    let output = run_cli_with_default_workspace(&["ls", "explicit/workspace", "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("auth") || stderr.contains("token"),
        "Expected auth error, got: {}",
        stderr
    );
    assert!(!stderr.contains("required arguments were not provided"));
}

// Test that flags can be in any position
#[test]
fn test_save_with_flags_before_tag_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_path, "test").expect("Failed to create test file");

    let arg = format!("test-tag:{}", test_path.display());
    let output = run_cli_with_default_workspace(&["save", "-v", &arg]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required arguments were not provided")
            && !stderr.contains("<PATH_TAG_PAIRS>")
    );
}

// Test mixed flags and positional args
#[test]
fn test_save_with_flags_mixed_positions() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_path, "test").expect("Failed to create test file");

    let arg = format!("test-tag:{}", test_path.display());
    let output = run_cli_with_default_workspace(&["save", "--force", &arg, "-v"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required arguments were not provided")
            && !stderr.contains("<PATH_TAG_PAIRS>")
    );
}

// Test that delete with workspace-like tag doesn't inject
#[test]
fn test_delete_with_workspace_format_tag() {
    let output = run_cli_with_default_workspace(&["delete", "org/tag-name"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // When tag contains '/', it should be treated as workspace (first positional arg),
    // so it needs a second positional arg for tags, which is missing
    // This should result in argument parsing error for missing <TAGS>
    assert!(
        stderr.contains("required arguments were not provided") || stderr.contains("<TAGS>"),
        "Expected missing TAGS error since org/tag-name is treated as workspace, got: {}",
        stderr
    );
}

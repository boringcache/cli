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

fn apply_test_env(cmd: &mut Command) -> &mut Command {
    if std::env::var("BORINGCACHE_API_URL").is_err() {
        cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL);
    }
    cmd.env("BORINGCACHE_TEST_MODE", "1")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN");
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

#[test]
fn test_run_dry_run_uses_project_workspace_for_inferred_bundle_install() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["run", "--dry-run", "--", "bundle", "install"])
        .output()
        .expect("Failed to execute inferred run dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let canonical_temp_dir = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize temp dir");
    let expected_pair = format!(
        "bundler:{}",
        canonical_temp_dir.join("vendor/bundle").display()
    );
    assert!(stdout.contains("boringcache restore test-org/test-workspace"));
    assert!(stdout.contains(&expected_pair), "stdout: {stdout}");
    assert!(stdout.contains(&format!(
        "env BUNDLE_PATH={}",
        canonical_temp_dir.join("vendor/bundle").display()
    )));
}

#[test]
fn test_run_dry_run_uses_profile_from_project_config() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[entries.bundler]
tag = "bundler-gems"

[profiles.bundle-install]
entries = ["bundler"]
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "--profile",
            "bundle-install",
            "--dry-run",
            "--",
            "boringcache-command-does-not-exist",
        ])
        .output()
        .expect("Failed to execute profile run dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let canonical_temp_dir = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize temp dir");
    let expected_pair = format!(
        "bundler-gems:{}",
        canonical_temp_dir.join("vendor/bundle").display()
    );
    assert!(stdout.contains("boringcache restore test-org/test-workspace"));
    assert!(stdout.contains(&expected_pair), "stdout: {stdout}");
    assert!(stdout.contains(&format!(
        "env BUNDLE_PATH={}",
        canonical_temp_dir.join("vendor/bundle").display()
    )));
}

#[test]
fn test_run_dry_run_does_not_add_inferred_entries_when_tag_paths_are_explicit() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"
"#,
    )
    .expect("write repo config");

    let explicit_pair = "custom-bundle:/tmp/custom-bundle";
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["run", explicit_pair, "--dry-run", "--", "bundle", "install"])
        .output()
        .expect("Failed to execute explicit run dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(explicit_pair), "stdout: {stdout}");
    assert!(!stdout.contains("vendor/bundle"), "stdout: {stdout}");
}

#[test]
fn test_run_rejects_manual_tags_with_profile() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[profiles.bundle-install]
entries = ["bundler"]
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "custom:/tmp/custom",
            "--profile",
            "bundle-install",
            "--dry-run",
            "--",
            "bundle",
            "install",
        ])
        .output()
        .expect("Failed to execute mixed-mode run command");

    assert!(
        !output.status.success(),
        "Mixed manual/profile mode should fail, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Do not combine manual TAG_PATH_PAIRS with --entry or --profile"),
        "stderr: {stderr}"
    );
}

use serde_json::Value;
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
fn test_run_dry_run_json_resolves_builtin_entry_without_command() {
    let temp_dir = TempDir::new().expect("temp dir");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "test-org/test-workspace",
            "--entry",
            "bundler",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    let canonical_temp_dir = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize temp dir");
    let expected_pair = format!(
        "bundler:{}",
        canonical_temp_dir.join("vendor/bundle").display()
    );

    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["workspace_source"], "explicit");
    assert_eq!(parsed["command"], serde_json::json!([]));
    assert_eq!(parsed["tag_path_pairs"], serde_json::json!([expected_pair]));
    assert_eq!(parsed["archive_entries"][0]["requested"], "bundler");
    assert_eq!(parsed["archive_entries"][0]["request_source"], "entry");
    assert_eq!(
        parsed["archive_entries"][0]["resolution_source"],
        "built-in"
    );
    assert_eq!(parsed["archive_entries"][0]["tag"], "bundler");
    assert_eq!(
        parsed["archive_entries"][0]["path"],
        canonical_temp_dir
            .join("vendor/bundle")
            .display()
            .to_string()
    );
    assert_eq!(parsed["archive_entries"][0]["tag_path_pair"], expected_pair);
    assert_eq!(
        parsed["env_vars"]["BUNDLE_PATH"],
        canonical_temp_dir
            .join("vendor/bundle")
            .display()
            .to_string()
    );
}

#[test]
fn test_run_dry_run_json_uses_profile_from_project_config_without_command() {
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
        .args(["run", "--profile", "bundle-install", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute profile json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    let canonical_temp_dir = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize temp dir");
    let expected_pair = format!(
        "bundler-gems:{}",
        canonical_temp_dir.join("vendor/bundle").display()
    );

    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["workspace_source"], "repo-config");
    let repo_config_path = parsed["repo_config_path"]
        .as_str()
        .expect("repo_config_path should be present");
    assert!(
        repo_config_path.ends_with(".boringcache.toml"),
        "repo_config_path: {repo_config_path}"
    );
    assert_eq!(parsed["command"], serde_json::json!([]));
    assert_eq!(parsed["tag_path_pairs"], serde_json::json!([expected_pair]));
    assert_eq!(parsed["archive_entries"][0]["requested"], "bundler");
    assert_eq!(parsed["archive_entries"][0]["request_source"], "profile");
    assert_eq!(parsed["archive_entries"][0]["profile"], "bundle-install");
    assert_eq!(
        parsed["archive_entries"][0]["resolution_source"],
        "repo-config"
    );
    assert_eq!(parsed["archive_entries"][0]["tag"], "bundler-gems");
    assert_eq!(
        parsed["archive_entries"][0]["path"],
        canonical_temp_dir
            .join("vendor/bundle")
            .display()
            .to_string()
    );
    assert_eq!(parsed["archive_entries"][0]["tag_path_pair"], expected_pair);
    assert_eq!(
        parsed["env_vars"]["BUNDLE_PATH"],
        canonical_temp_dir
            .join("vendor/bundle")
            .display()
            .to_string()
    );
}

#[test]
fn test_run_dry_run_json_marks_manual_pairs_as_manual() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "custom-tag:/tmp/custom-path",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute manual json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["workspace_source"], "explicit");
    assert_eq!(
        parsed["tag_path_pairs"],
        serde_json::json!(["custom-tag:/tmp/custom-path"])
    );
    assert_eq!(parsed["archive_entries"][0]["requested"], "custom-tag");
    assert_eq!(parsed["archive_entries"][0]["request_source"], "manual");
    assert_eq!(parsed["archive_entries"][0]["resolution_source"], "manual");
    assert_eq!(parsed["archive_entries"][0]["tag"], "custom-tag");
    assert_eq!(parsed["archive_entries"][0]["path"], "/tmp/custom-path");
    assert_eq!(
        parsed["archive_entries"][0]["tag_path_pair"],
        "custom-tag:/tmp/custom-path"
    );
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

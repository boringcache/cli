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
    if std::env::var("BORINGCACHE_API_URL").is_err() {
        cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL);
    }
    cmd.env("BORINGCACHE_TEST_MODE", "1")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN");
    cmd
}

fn assert_schema_version(parsed: &Value) {
    assert_eq!(parsed["schema_version"], 1);
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
    assert_schema_version(&parsed);
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
    assert_eq!(parsed["archive_entries"][0]["resolved_tag"], "bundler");
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
    assert_schema_version(&parsed);
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
    assert_eq!(parsed["archive_entries"][0]["resolved_tag"], "bundler-gems");
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
fn test_run_dry_run_json_allows_workspace_only_plan_from_repo_config() {
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
        .args(["run", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute workspace-only json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
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
    assert_eq!(parsed["tag_path_pairs"], serde_json::json!([]));
    assert!(parsed.get("archive_entries").is_none());
    assert_eq!(parsed["env_vars"], serde_json::json!({}));
    assert!(parsed.get("proxy").is_none());
}

#[test]
fn test_run_dry_run_json_reports_proxy_startup_mode() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "tool-cache",
            "--on-demand",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute proxy-only json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["proxy"]["tag"], "tool-cache");
    assert_eq!(parsed["proxy"]["startup_mode"], "on-demand");
}

#[test]
fn test_run_dry_run_json_reports_oci_prefetch_refs() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "tool-cache",
            "--oci-prefetch-ref",
            "library/ubuntu@latest",
            "--oci-prefetch-ref",
            "node@sha256:abcdef",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute proxy-only json-dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_eq!(
        parsed["proxy"]["oci_prefetch_refs"],
        serde_json::json!(["library/ubuntu@latest", "node@sha256:abcdef"])
    );
}

#[test]
fn test_run_dry_run_rejects_invalid_oci_prefetch_ref() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "--proxy",
            "tool-cache",
            "--oci-prefetch-ref",
            "badref",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute invalid dry-run command");

    assert!(
        !output.status.success(),
        "Expected invalid prefetch ref to fail, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Invalid OCI prefetch ref format"),
        "Expected validation error in stderr: {}",
        String::from_utf8_lossy(&output.stderr)
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
    assert_schema_version(&parsed);
    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["workspace_source"], "explicit");
    assert_eq!(
        parsed["tag_path_pairs"],
        serde_json::json!(["custom-tag:/tmp/custom-path"])
    );
    assert_eq!(parsed["archive_entries"][0]["requested"], "custom-tag");
    assert_eq!(parsed["archive_entries"][0]["request_source"], "manual");
    assert_eq!(parsed["archive_entries"][0]["resolution_source"], "manual");
    assert_eq!(parsed["archive_entries"][0]["resolved_tag"], "custom-tag");
    assert_eq!(parsed["archive_entries"][0]["tag"], "custom-tag");
    assert_eq!(parsed["archive_entries"][0]["path"], "/tmp/custom-path");
    assert_eq!(
        parsed["archive_entries"][0]["tag_path_pair"],
        "custom-tag:/tmp/custom-path"
    );
}

#[test]
fn test_run_dry_run_json_applies_hidden_tag_decoration_flags() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "bundler:vendor/bundle",
            "--cache-tag",
            "web",
            "--tool-tag-suffix",
            "ruby-4.0.1",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute decorated manual json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(
        parsed["tag_path_pairs"],
        serde_json::json!(["web-bundler-ruby-4.0.1:vendor/bundle"])
    );
    assert_eq!(parsed["archive_entries"][0]["request_source"], "manual");
    assert_eq!(parsed["archive_entries"][0]["resolved_tag"], "bundler");
    assert_eq!(
        parsed["archive_entries"][0]["tag"],
        "web-bundler-ruby-4.0.1"
    );
    assert_eq!(parsed["archive_entries"][0]["path"], "vendor/bundle");
}

#[test]
fn test_run_dry_run_json_plans_archive_paths_and_restore_prefixes() {
    let temp_dir = TempDir::new().expect("temp dir");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "test-org/test-workspace",
            "--archive-path",
            "node_modules",
            "--archive-path",
            ".npm-cache",
            "--archive-tag-prefix",
            "deps",
            "--archive-restore-prefix",
            "deps-fallback",
            "--no-platform",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute archive planner json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    let canonical_temp_dir = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize temp dir");
    let primary_pairs = vec![
        format!(
            "deps-node-modules:{}",
            canonical_temp_dir.join("node_modules").display()
        ),
        format!(
            "deps-npm-cache:{}",
            canonical_temp_dir.join(".npm-cache").display()
        ),
    ];
    let restore_pairs = vec![
        format!(
            "deps-fallback-node-modules:{}",
            canonical_temp_dir.join("node_modules").display()
        ),
        format!(
            "deps-fallback-npm-cache:{}",
            canonical_temp_dir.join(".npm-cache").display()
        ),
    ];

    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["tag_path_pairs"], serde_json::json!(primary_pairs));
    assert_eq!(
        parsed["archive_entries"][0]["request_source"],
        "archive-path"
    );
    assert_eq!(parsed["archive_entries"][0]["tag"], "deps-node-modules");
    assert_eq!(parsed["archive_entries"][1]["tag"], "deps-npm-cache");
    assert_eq!(
        parsed["archive_restore_candidates"][0]["tag_prefix"],
        "deps-fallback"
    );
    assert_eq!(
        parsed["archive_restore_candidates"][0]["tag_path_pairs"],
        serde_json::json!(restore_pairs)
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
fn test_run_dry_run_json_applies_cache_tag_and_tool_suffix_to_planned_entries() {
    let temp_dir = TempDir::new().expect("temp dir");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "test-org/test-workspace",
            "--entry",
            "node-modules",
            "--cache-tag",
            "web",
            "--tool-tag-suffix",
            "node-22.4.1-ruby-3.3.6",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute decorated planned-entry json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    let expected_pair = "web-node-modules-node-22.4.1-ruby-3.3.6:node_modules";

    assert_eq!(parsed["tag_path_pairs"], serde_json::json!([expected_pair]));
    assert_eq!(parsed["archive_entries"][0]["requested"], "node_modules");
    assert_eq!(parsed["archive_entries"][0]["resolved_tag"], "node_modules");
    assert_eq!(
        parsed["archive_entries"][0]["tag"],
        "web-node-modules-node-22.4.1-ruby-3.3.6"
    );
    assert_eq!(parsed["archive_entries"][0]["tag_path_pair"], expected_pair);
}

#[test]
fn test_run_dry_run_json_applies_cache_tag_and_tool_suffix_to_manual_pairs() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "run",
            "test-org/test-workspace",
            "bundler:vendor/bundle",
            "--cache-tag",
            "web",
            "--tool-tag-suffix",
            "ruby-4.0.1",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute decorated manual json dry-run command");

    assert!(
        output.status.success(),
        "JSON dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(
        parsed["tag_path_pairs"],
        serde_json::json!(["web-bundler-ruby-4.0.1:vendor/bundle"])
    );
    assert_eq!(parsed["archive_entries"][0]["requested"], "bundler");
    assert_eq!(parsed["archive_entries"][0]["resolved_tag"], "bundler");
    assert_eq!(
        parsed["archive_entries"][0]["tag"],
        "web-bundler-ruby-4.0.1"
    );
    assert_eq!(
        parsed["archive_entries"][0]["tag_path_pair"],
        "web-bundler-ruby-4.0.1:vendor/bundle"
    );
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

#[test]
fn test_turbo_dry_run_json_uses_adapter_config() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.turbo]
tag = "turbo-main"
command = ["pnpm", "turbo", "run", "build"]
entries = ["pnpm-store"]
metadata-hints = ["phase=warm"]
fail-on-cache-error = true
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["turbo", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute turbo dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "turbo");
    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["tag"], "turbo-main");
    assert_eq!(parsed["command"][0], "pnpm");
    assert_eq!(parsed["env_vars"]["TURBO_API"], "http://127.0.0.1:5000");
    assert_eq!(parsed["env_vars"]["TURBO_TOKEN"], "boringcache");
    assert_eq!(parsed["proxy"]["no_platform"], false);
    assert_eq!(parsed["proxy"]["no_git"], false);
    assert_eq!(parsed["proxy"]["startup_mode"], "warm");
    assert_eq!(parsed["proxy"]["metadata_hints"]["phase"], "warm");
}

#[test]
fn test_turbo_dry_run_json_reports_on_demand_proxy_mode() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "turbo",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "turbo-main",
            "--on-demand",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute turbo on-demand dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "turbo");
    assert_eq!(parsed["proxy"]["startup_mode"], "on-demand");
}

#[test]
fn test_nx_dry_run_json_injects_remote_cache_env() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.nx]
tag = "nx-cache"
command = ["nx", "run", "app:build"]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["nx", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute nx dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "nx");
    assert_eq!(parsed["tag"], "nx-cache");
    assert_eq!(
        parsed["command"],
        serde_json::json!(["nx", "run", "app:build"])
    );
    assert_eq!(
        parsed["env_vars"]["NX_SELF_HOSTED_REMOTE_CACHE_SERVER"],
        "http://host.docker.internal:6001"
    );
    assert_eq!(
        parsed["env_vars"]["NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN"],
        "boringcache"
    );
}

#[test]
fn test_sccache_dry_run_json_injects_webdav_env() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.sccache]
tag = "sccache-cache"
command = ["cargo", "build"]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["sccache", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute sccache dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "sccache");
    assert_eq!(parsed["tag"], "sccache-cache");
    assert_eq!(parsed["command"], serde_json::json!(["cargo", "build"]));
    assert_eq!(parsed["env_vars"]["RUSTC_WRAPPER"], "sccache");
    assert_eq!(
        parsed["env_vars"]["SCCACHE_WEBDAV_ENDPOINT"],
        "http://host.docker.internal:6001/"
    );
}

#[test]
fn test_go_dry_run_json_injects_gocacheprog_env() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.go]
tag = "go-cache"
command = ["go", "test", "./..."]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["go", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute go dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "go");
    assert_eq!(parsed["tag"], "go-cache");
    assert_eq!(
        parsed["command"],
        serde_json::json!(["go", "test", "./..."])
    );
    assert_eq!(
        parsed["env_vars"]["GOCACHEPROG"],
        "boringcache go-cacheprog --endpoint http://host.docker.internal:6001"
    );
}

#[test]
fn test_adapter_dry_run_json_reports_oci_prefetch_refs() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "turbo",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "turbo-main",
            "--oci-prefetch-ref",
            "cache@buildcache",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute turbo dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(
        parsed["proxy"]["oci_prefetch_refs"],
        serde_json::json!(["cache@buildcache"])
    );
    assert_eq!(parsed["proxy"]["oci_hydration"], "metadata-only");
}

#[test]
fn test_adapter_dry_run_json_replaces_configured_entry_list_and_merges_metadata_hints() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.turbo]
tag = "turbo-main"
command = ["pnpm", "turbo", "run", "build"]
entries = ["pnpm-store"]
metadata-hints = ["phase=warm", "tool=turbo"]
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "turbo",
            "--entry",
            "bundler",
            "--metadata-hint",
            "phase=ready",
            "--metadata-hint",
            "lane=ci",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("Failed to execute turbo dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    let entries = parsed["archive_entries"]
        .as_array()
        .expect("archive_entries should be an array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["requested"], "bundler");
    assert_eq!(parsed["proxy"]["metadata_hints"]["phase"], "ready");
    assert_eq!(parsed["proxy"]["metadata_hints"]["tool"], "turbo");
    assert_eq!(parsed["proxy"]["metadata_hints"]["lane"], "ci");
}

#[test]
fn test_bazel_dry_run_json_substitutes_placeholders_from_adapter_config_command() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.bazel]
tag = "bazel-cache"
command = ["bazel", "build", "--remote_cache={ENDPOINT}", "--remote_instance_name={CACHE_REF}", "//..."]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["bazel", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute bazel dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "bazel");
    assert_eq!(parsed["tag"], "bazel-cache");
    assert_eq!(parsed["proxy"]["endpoint_host"], "host.docker.internal");
    assert_eq!(parsed["proxy"]["port"], 6001);
    let command = parsed["command"]
        .as_array()
        .expect("command should be an array");
    assert_eq!(command[0], "bazel");
    let command_strings: Vec<&str> = command
        .iter()
        .map(|value| value.as_str().expect("command args should be strings"))
        .collect();
    assert!(
        command_strings.contains(&"--remote_cache=http://host.docker.internal:6001"),
        "command args: {command_strings:?}"
    );
    let cache_ref_arg = command_strings
        .iter()
        .copied()
        .find(|arg| arg.starts_with("--remote_instance_name="))
        .expect("cache ref arg should be present");
    assert!(
        cache_ref_arg
            .starts_with("--remote_instance_name=host.docker.internal:6001/cache:bazel-cache"),
        "cache_ref_arg: {cache_ref_arg}"
    );
    assert!(
        !cache_ref_arg.contains("{CACHE_REF}"),
        "cache_ref_arg: {cache_ref_arg}"
    );
}

#[test]
fn test_bazel_dry_run_json_injects_remote_cache_flags_by_default() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.bazel]
tag = "bazel-cache"
command = ["bazel", "build", "//..."]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["bazel", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute bazel dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    let command = parsed["command"]
        .as_array()
        .expect("command should be an array");
    assert_eq!(command[0], "bazel");
    assert_eq!(command[1], "build");
    assert_eq!(
        command[2],
        "--remote_cache=http://host.docker.internal:6001"
    );
    assert_eq!(command[3], "--remote_upload_local_results=true");
    assert_eq!(command[4], "//...");
}

#[test]
fn test_gradle_dry_run_json_injects_init_script_and_env() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.gradle]
tag = "gradle-cache"
command = ["./gradlew", "build", "--no-daemon"]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["gradle", "--read-only", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute gradle dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    let command = parsed["command"]
        .as_array()
        .expect("command should be an array");
    assert_eq!(command[0], "./gradlew");
    assert_eq!(command[1], "--build-cache");
    assert!(
        command[2]
            .as_str()
            .is_some_and(|value| value.starts_with("--init-script="))
    );
    assert_eq!(
        parsed["env_vars"]["BORINGCACHE_GRADLE_CACHE_URL"],
        "http://host.docker.internal:6001/cache/"
    );
    assert_eq!(parsed["env_vars"]["BORINGCACHE_GRADLE_CACHE_PUSH"], "false");
}

#[test]
fn test_maven_dry_run_json_injects_remote_cache_properties() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::write(
        temp_dir.path().join(".boringcache.toml"),
        r#"
workspace = "test-org/test-workspace"

[adapters.maven]
tag = "maven-cache"
command = ["mvn", "install", "-DskipTests"]
endpoint-host = "host.docker.internal"
port = 6001
"#,
    )
    .expect("write repo config");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args(["maven", "--read-only", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute maven dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    let command = parsed["command"]
        .as_array()
        .expect("command should be an array");
    let args = command
        .iter()
        .skip(1)
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(args.contains(&"-Dmaven.build.cache.enabled=true"));
    assert!(args.contains(&"-Dmaven.build.cache.remote.enabled=true"));
    assert!(args.contains(&"-Dmaven.build.cache.remote.url=http://host.docker.internal:6001"));
    assert!(args.contains(&"-Dmaven.build.cache.remote.save.enabled=false"));
}

#[test]
fn test_turbo_dry_run_json_plans_default_tag_without_command() {
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
        .env("GITHUB_REPOSITORY", "owner/demo-app")
        .args(["turbo", "--dry-run", "--json"])
        .output()
        .expect("Failed to execute turbo planner command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "turbo");
    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["tag"], "demo-app");
    assert_eq!(parsed["command"], serde_json::json!([]));
    assert_eq!(parsed["proxy"]["host"], "127.0.0.1");
    assert_eq!(parsed["proxy"]["endpoint_host"], "127.0.0.1");
    assert_eq!(parsed["proxy"]["port"], 5000);
    assert_eq!(parsed["proxy"]["no_platform"], false);
    assert_eq!(parsed["proxy"]["no_git"], false);
    assert_eq!(parsed["proxy"]["read_only"], false);
    assert_eq!(parsed["env_vars"]["TURBO_API"], "http://127.0.0.1:5000");
    assert_eq!(parsed["env_vars"]["TURBO_TOKEN"], "boringcache");
    assert_eq!(parsed["env_vars"]["TURBO_TEAM"], "boringcache");
}

#[test]
fn test_docker_dry_run_json_injects_cache_flags() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "docker",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "docker-main",
            "--endpoint-host",
            "host.docker.internal",
            "--dry-run",
            "--json",
            "--",
            "docker",
            "buildx",
            "build",
            ".",
        ])
        .output()
        .expect("Failed to execute docker dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "docker");
    assert_eq!(parsed["tag"], "docker-main");
    assert_eq!(parsed["proxy"]["endpoint_host"], "host.docker.internal");
    assert_eq!(
        parsed["oci_cache"]["registry_ref"],
        "host.docker.internal:5000/cache:buildcache"
    );
    assert_eq!(
        parsed["oci_cache"]["cache_from"],
        "type=registry,ref=host.docker.internal:5000/cache:buildcache"
    );
    assert_eq!(
        parsed["oci_cache"]["cache_to"],
        "type=registry,ref=host.docker.internal:5000/cache:buildcache,mode=max"
    );
    assert_eq!(
        parsed["proxy"]["oci_prefetch_refs"],
        serde_json::json!(["cache@buildcache"])
    );
    let command = parsed["command"]
        .as_array()
        .expect("command array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(
        command
            .contains(&"--cache-from=type=registry,ref=host.docker.internal:5000/cache:buildcache")
    );
    assert!(command.contains(
        &"--cache-to=type=registry,ref=host.docker.internal:5000/cache:buildcache,mode=max"
    ));
}

#[test]
fn test_docker_read_only_dry_run_json_uses_on_demand_proxy_mode() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "docker",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "docker-main",
            "--endpoint-host",
            "host.docker.internal",
            "--read-only",
            "--dry-run",
            "--json",
            "--",
            "docker",
            "buildx",
            "build",
            ".",
        ])
        .output()
        .expect("Failed to execute docker read-only dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "docker");
    assert_eq!(parsed["proxy"]["read_only"], true);
    assert_eq!(parsed["proxy"]["startup_mode"], "on-demand");
    assert_eq!(parsed["proxy"]["oci_hydration"], "metadata-only");
    assert!(parsed["proxy"].get("oci_prefetch_refs").is_none());
    assert!(parsed["oci_cache"].get("cache_to").is_none());

    let command = parsed["command"]
        .as_array()
        .expect("command array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(
        command
            .contains(&"--cache-from=type=registry,ref=host.docker.internal:5000/cache:buildcache")
    );
    assert!(!command.iter().any(|arg| arg.starts_with("--cache-to=")));
}

#[test]
fn test_docker_dry_run_json_reports_oci_hydration_policy() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "docker",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "docker-main",
            "--endpoint-host",
            "host.docker.internal",
            "--oci-hydration",
            "bodies-before-ready",
            "--dry-run",
            "--json",
            "--",
            "docker",
            "buildx",
            "build",
            ".",
        ])
        .output()
        .expect("Failed to execute docker dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_schema_version(&parsed);
    assert_eq!(parsed["adapter"], "docker");
    assert_eq!(parsed["proxy"]["oci_hydration"], "bodies-before-ready");
    assert_eq!(
        parsed["proxy"]["oci_prefetch_refs"],
        serde_json::json!(["cache@buildcache"])
    );
}

#[test]
fn test_docker_dry_run_rejects_embedded_ref_tag_syntax() {
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .args([
            "docker",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "docker-main:cache-main",
            "--dry-run",
            "--json",
            "--",
            "docker",
            "buildx",
            "build",
            ".",
        ])
        .output()
        .expect("Failed to execute docker dry-run command");

    assert!(
        !output.status.success(),
        "Dry-run should fail, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "Use --tag for the proxy cache tag and --cache-ref-tag for the OCI cache tag"
        ),
        "stderr: {stderr}"
    );
}

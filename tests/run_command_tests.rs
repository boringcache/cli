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
    assert_eq!(parsed["adapter"], "turbo");
    assert_eq!(parsed["workspace"], "test-org/test-workspace");
    assert_eq!(parsed["tag"], "turbo-main");
    assert_eq!(parsed["command"][0], "pnpm");
    assert_eq!(parsed["env_vars"]["TURBO_API"], "http://127.0.0.1:5000");
    assert_eq!(parsed["env_vars"]["TURBO_TOKEN"], "boringcache");
    assert_eq!(parsed["proxy"]["no_platform"], false);
    assert_eq!(parsed["proxy"]["no_git"], false);
    assert_eq!(parsed["proxy"]["metadata_hints"]["phase"], "warm");
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
    assert_eq!(parsed["adapter"], "bazel");
    assert_eq!(parsed["tag"], "bazel-cache");
    assert_eq!(parsed["proxy"]["endpoint_host"], "host.docker.internal");
    assert_eq!(parsed["proxy"]["port"], 6001);
    assert_eq!(parsed["command"][0], "bazel");
    assert_eq!(
        parsed["command"][2],
        "--remote_cache=http://host.docker.internal:6001"
    );
    let cache_ref_arg = parsed["command"][3]
        .as_str()
        .expect("cache ref arg should be a string");
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
fn test_docker_dry_run_json_supports_embedded_ref_tag_compatibility() {
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
        .expect("Failed to execute docker compatibility dry-run command");

    assert!(
        output.status.success(),
        "Dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parse json output");
    assert_eq!(parsed["tag"], "docker-main");
    assert_eq!(parsed["oci_cache"]["ref_tag"], "cache-main");
    assert_eq!(
        parsed["oci_cache"]["registry_ref"],
        "127.0.0.1:5000/cache:cache-main"
    );
}

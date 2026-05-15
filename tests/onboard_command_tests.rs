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
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_ADMIN_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN");
    cmd
}

#[test]
fn onboard_workspace_apply_writes_repo_workspace_config_without_ci_files() {
    let temp_dir = TempDir::new().expect("temp dir");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .env("HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .args([
            "onboard",
            "--workspace",
            "boringcache/benchmark-hugo",
            "--apply",
            "--json",
        ])
        .output()
        .expect("run onboard --workspace --apply --json");

    assert!(
        output.status.success(),
        "onboard should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = std::fs::read_to_string(temp_dir.path().join(".boringcache.toml"))
        .expect("read repo config");
    assert!(
        config.contains("workspace = \"boringcache/benchmark-hugo\""),
        "config: {config}"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse onboard json");
    assert_eq!(
        body["repo_config"]["workspace"],
        "boringcache/benchmark-hugo"
    );
    assert_eq!(body["repo_config"]["wrote"], true);
    let steps = json_string_array(&body["next_steps"]);
    assert!(steps.contains(&"Review .boringcache.toml before committing."));
    assert!(
        steps
            .iter()
            .any(|step| step.contains("boringcache doctor --json")),
        "next_steps: {steps:?}"
    );
}

#[test]
fn onboard_workspace_apply_writes_repo_workspace_config_when_ci_needs_no_changes() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(temp_dir.path().join(".github/workflows")).expect("workflow dir");
    std::fs::write(
        temp_dir.path().join(".github/workflows/ci.yml"),
        "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo ok\n",
    )
    .expect("write workflow");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .env("HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .args([
            "onboard",
            "--workspace",
            "boringcache/benchmark-hugo",
            "--apply",
            "--json",
        ])
        .output()
        .expect("run onboard --workspace --apply --json");

    assert!(
        output.status.success(),
        "onboard should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = std::fs::read_to_string(temp_dir.path().join(".boringcache.toml"))
        .expect("read repo config");
    assert!(
        config.contains("workspace = \"boringcache/benchmark-hugo\""),
        "config: {config}"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse onboard json");
    assert_eq!(
        body["repo_config"]["workspace"],
        "boringcache/benchmark-hugo"
    );
    assert_eq!(body["repo_config"]["wrote"], true);
}

#[test]
fn onboard_workspace_apply_json_reports_agent_safe_next_steps() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(temp_dir.path().join(".github/workflows")).expect("workflow dir");
    std::fs::write(
        temp_dir.path().join(".github/workflows/ci.yml"),
        "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/cache@v4\n        with:\n          path: node_modules\n          key: node-${{ runner.os }}-${{ hashFiles('package-lock.json') }}\n      - run: npm ci\n",
    )
    .expect("write workflow");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .env("HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .args([
            "onboard",
            "--workspace",
            "boringcache/benchmark-hugo",
            "--apply",
            "--json",
        ])
        .output()
        .expect("run onboard --workspace --apply --json");

    assert!(
        output.status.success(),
        "onboard should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let workflow = std::fs::read_to_string(temp_dir.path().join(".github/workflows/ci.yml"))
        .expect("read optimized workflow");
    assert!(
        workflow.contains("uses: boringcache/one@v1"),
        "workflow: {workflow}"
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse onboard json");
    assert_eq!(body["optimize_results"][0]["status"], "optimized");
    let steps = json_string_array(&body["next_steps"]);
    assert!(steps.contains(&"Review .boringcache.toml before committing."));
    assert!(steps.contains(&"Review the generated workflow diff before committing."));
    assert!(
        steps
            .iter()
            .any(|step| step.contains("Make sure CI has BORINGCACHE_RESTORE_TOKEN")),
        "next_steps: {steps:?}"
    );
}

#[test]
fn onboard_apply_seeds_repo_config_from_scanned_manual_tags() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(temp_dir.path().join(".github/workflows")).expect("workflow dir");

    std::fs::write(
        temp_dir.path().join(".github/workflows/ci.yml"),
        r#"
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: node-${{ runner.os }}-${{ hashFiles('package-lock.json') }}
      - run: |
          boringcache run my-org/my-app bundler:/usr/local/bundle -- bundle install
      - run: npm ci
"#,
    )
    .expect("write workflow");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .env("HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .args(["onboard", "--apply"])
        .output()
        .expect("run onboard --apply");

    assert!(
        output.status.success(),
        "onboard --apply should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let workflow = std::fs::read_to_string(temp_dir.path().join(".github/workflows/ci.yml"))
        .expect("read optimized workflow");
    assert!(
        workflow.contains("uses: boringcache/one@v1"),
        "workflow: {workflow}"
    );

    let config = std::fs::read_to_string(temp_dir.path().join(".boringcache.toml"))
        .expect("read repo config");
    assert!(
        config.contains("[profiles.bundle-install]"),
        "config: {config}"
    );
    assert!(
        config.contains("entries = [\"bundler\"]"),
        "config: {config}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Seeded repo config:"), "stdout: {stdout}");
}

#[test]
fn onboard_apply_ignores_dockerfiles_and_handles_actions_workflow() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(temp_dir.path().join(".github/workflows")).expect("workflow dir");
    std::fs::create_dir_all(temp_dir.path().join("images/app")).expect("docker dir");

    std::fs::write(
        temp_dir.path().join(".github/workflows/ci.yml"),
        r#"
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: vendor/bundle
          key: bundler-${{ runner.os }}-${{ hashFiles('**/Gemfile.lock') }}
      - run: bundle install
"#,
    )
    .expect("write workflow");

    std::fs::write(
        temp_dir.path().join("images/app/Dockerfile"),
        r#"
FROM node:20
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
"#,
    )
    .expect("write dockerfile");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .env("HOME", temp_dir.path())
        .current_dir(temp_dir.path())
        .args(["onboard", "--apply"])
        .output()
        .expect("run onboard --apply");

    assert!(
        output.status.success(),
        "onboard --apply should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let workflow = std::fs::read_to_string(temp_dir.path().join(".github/workflows/ci.yml"))
        .expect("read optimized workflow");
    assert!(
        workflow.contains("uses: boringcache/one@v1"),
        "workflow: {workflow}"
    );
    assert!(
        workflow.contains("BORINGCACHE_RESTORE_TOKEN: ${{ secrets.BORINGCACHE_RESTORE_TOKEN }}"),
        "workflow: {workflow}"
    );
    assert!(
        !workflow.contains("BORINGCACHE_SAVE_TOKEN: ${{ secrets.BORINGCACHE_SAVE_TOKEN }}"),
        "workflow should not add a save token by default: {workflow}"
    );

    assert!(
        !temp_dir.path().join(".boringcache.toml").exists(),
        "Dockerfiles should not seed repo config"
    );
}

fn json_string_array(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_array()
        .expect("json value should be an array")
        .iter()
        .map(|step| step.as_str().expect("array value should be a string"))
        .collect()
}

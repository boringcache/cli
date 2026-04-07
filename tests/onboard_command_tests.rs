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
        .env_remove("BORINGCACHE_API_TOKEN")
        .env_remove("BORINGCACHE_ADMIN_TOKEN")
        .env_remove("BORINGCACHE_TOKEN_FILE")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN");
    cmd
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
fn onboard_apply_handles_repo_with_dockerfile_and_actions_workflow() {
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
FROM ghcr.io/boringcache/base:bookworm-build
RUN boringcache run my-org/my-app mise-installs:/mise/installs --no-platform --no-git -- \
    mise install
RUN boringcache run my-org/my-app bundler:/usr/local/bundle --no-platform --no-git -- \
    bundle install
RUN boringcache run my-org/my-app node_modules:node_modules --no-platform --no-git -- \
    yarn install --frozen-lockfile
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
        workflow.contains("BORINGCACHE_SAVE_TOKEN: ${{ github.event_name == 'pull_request' && '' || secrets.BORINGCACHE_SAVE_TOKEN }}"),
        "workflow: {workflow}"
    );

    let config = std::fs::read_to_string(temp_dir.path().join(".boringcache.toml"))
        .expect("read repo config");
    assert!(config.contains("[entries.mise]"), "config: {config}");
    assert!(
        config.contains("default_path = \"/mise/installs\""),
        "config: {config}"
    );
    assert!(
        config.contains("[profiles.bundle-install]"),
        "config: {config}"
    );
    assert!(
        config.contains("[profiles.mise-install]"),
        "config: {config}"
    );
    assert!(
        config.contains("[profiles.yarn-install]"),
        "config: {config}"
    );
}

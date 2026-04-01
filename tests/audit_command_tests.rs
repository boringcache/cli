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
fn audit_json_supports_explicit_paths_and_skips_dynamic_and_quoted_examples() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(temp_dir.path().join("images/examples/rails")).expect("images dir");
    std::fs::create_dir_all(temp_dir.path().join("scripts")).expect("scripts dir");
    std::fs::create_dir_all(temp_dir.path().join(".github/workflows")).expect("workflow dir");

    std::fs::write(
        temp_dir.path().join("images/examples/rails/Dockerfile"),
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

    std::fs::write(
        temp_dir.path().join("scripts/dynamic.sh"),
        r#"
boringcache run my-org/my-app "${TAG}:node_modules" -- npm ci
boringcache run my-org/my-app tag:path -- echo fallback
"#,
    )
    .expect("write script");

    std::fs::write(
        temp_dir.path().join(".github/workflows/release.yml"),
        r#"
jobs:
  release:
    steps:
      - run: |
          gh release create v1 \
            --notes "Example:

          boringcache run my-workspace \"node-deps:node_modules,build-cache:target\" -- npm test
          "
"#,
    )
    .expect("write workflow");

    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "audit",
            "--json",
            "--path",
            "images",
            "--path",
            "scripts",
            "--path",
            ".github/workflows",
        ])
        .output()
        .expect("run audit");

    assert!(
        output.status.success(),
        "audit should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"id\": \"bundler\""), "stdout: {stdout}");
    assert!(stdout.contains("\"id\": \"mise\""), "stdout: {stdout}");
    assert!(
        stdout.contains("\"id\": \"node_modules\""),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"name\": \"bundle-install\""),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"name\": \"mise-install\""),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"name\": \"yarn-install\""),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"skipped_dynamic_pairs\": 1"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"skipped_placeholder_pairs\": 1"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("node-deps"), "stdout: {stdout}");
}

#[test]
fn audit_write_generates_repo_config() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(temp_dir.path().join("images/examples/rails")).expect("images dir");

    std::fs::write(
        temp_dir.path().join("images/examples/rails/Dockerfile"),
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
        .current_dir(temp_dir.path())
        .args(["audit", "--write", "--path", "images"])
        .output()
        .expect("run audit --write");

    assert!(
        output.status.success(),
        "audit --write should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = std::fs::read_to_string(temp_dir.path().join(".boringcache.toml"))
        .expect("read generated repo config");
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
        config.contains("entries = [\"bundler\"]"),
        "config: {config}"
    );
    assert!(
        config.contains("[profiles.mise-install]"),
        "config: {config}"
    );
    assert!(config.contains("entries = [\"mise\"]"), "config: {config}");
    assert!(
        config.contains("[profiles.yarn-install]"),
        "config: {config}"
    );
    assert!(
        config.contains("entries = [\"node_modules\"]"),
        "config: {config}"
    );
}

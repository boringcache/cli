use serde_json::Value;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const DUMMY_API_URL: &str = "http://127.0.0.1:65535";
const CI_RUN_ENV_VARS: &[&str] = &[
    "BORINGCACHE_CI_PROVIDER",
    "BORINGCACHE_CI_RUN_ID",
    "BORINGCACHE_CI_RUN_ATTEMPT",
    "BORINGCACHE_CI_REPOSITORY",
    "BORINGCACHE_CI_REF",
    "BORINGCACHE_CI_REF_NAME",
    "BORINGCACHE_CI_REF_TYPE",
    "BORINGCACHE_CI_HEAD_REF",
    "BORINGCACHE_CI_BASE_REF",
    "BORINGCACHE_CI_DEFAULT_BRANCH",
    "BORINGCACHE_CI_PR_NUMBER",
    "BORINGCACHE_CI_SHA",
    "BORINGCACHE_CI_RUN_STARTED_AT",
    "BORINGCACHE_BENCHMARK_MODE",
    "GITHUB_ACTIONS",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "GITHUB_DEFAULT_BRANCH",
    "GITHUB_EVENT_PATH",
    "GITHUB_SHA",
];

struct Placeholder {
    value: String,
    placeholder: &'static str,
}

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
    cmd.env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .env_remove("BORINGCACHE_REQUIRE_SERVER_SIGNATURE")
        .env_remove("BORINGCACHE_RESTORE_TOKEN")
        .env_remove("BORINGCACHE_SAVE_TOKEN")
        .env_remove("CARGO_INCREMENTAL")
        .env_remove("CC")
        .env_remove("CXX");
    for name in CI_RUN_ENV_VARS {
        cmd.env_remove(name);
    }
    cmd
}

fn path_placeholder(path: &Path, placeholder: &'static str) -> Placeholder {
    Placeholder {
        value: path.to_string_lossy().into_owned(),
        placeholder,
    }
}

fn home_placeholder() -> Placeholder {
    let home = dirs::home_dir().expect("home dir");
    path_placeholder(&home, "$HOME")
}

fn workspace_root_placeholders(path: &Path) -> Vec<Placeholder> {
    let mut placeholders = Vec::new();
    if let Ok(canonical) = std::fs::canonicalize(path) {
        placeholders.push(path_placeholder(&canonical, "$WORKSPACE_ROOT"));
    }
    placeholders.push(path_placeholder(path, "$WORKSPACE_ROOT"));
    placeholders
}

fn assert_machine_output_matches_fixture(actual_stdout: &[u8], fixture: &str) {
    assert_machine_output_matches_fixture_with_placeholders(actual_stdout, fixture, &[]);
}

fn assert_machine_output_matches_fixture_with_placeholders(
    actual_stdout: &[u8],
    fixture: &str,
    placeholders: &[Placeholder],
) {
    let actual: Value = serde_json::from_slice(actual_stdout).expect("actual CLI JSON");
    let expected: Value = serde_json::from_str(fixture).expect("fixture JSON");
    let actual = normalize_machine_output(actual, placeholders);

    assert_eq!(
        actual, expected,
        "CLI machine output drifted. Review the consumer impact before updating this fixture."
    );
}

fn normalize_machine_output(mut value: Value, placeholders: &[Placeholder]) -> Value {
    match &mut value {
        Value::String(string) => {
            for placeholder in placeholders {
                if !placeholder.value.is_empty() {
                    *string = string.replace(&placeholder.value, placeholder.placeholder);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    value
}

fn normalize_machine_output_in_place(value: &mut Value, placeholders: &[Placeholder]) {
    match value {
        Value::String(string) => {
            for placeholder in placeholders {
                if !placeholder.value.is_empty() {
                    *string = string.replace(&placeholder.value, placeholder.placeholder);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                normalize_machine_output_in_place(value, placeholders);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[test]
fn run_dry_run_manual_archive_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "run",
            "test-org/test-workspace",
            "custom-tag:/tmp/custom-path",
            "--dry-run",
            "--json",
            "--",
            "echo",
            "hello",
        ])
        .output()
        .expect("run dry-run json");

    assert!(
        output.status.success(),
        "dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/run_dry_run_manual_archive_v1.json"),
    );
}

#[test]
fn docker_dry_run_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "docker",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "docker-cache",
            "--no-platform",
            "--no-git",
            "--dry-run",
            "--json",
            "--",
            "docker",
            "buildx",
            "build",
            ".",
        ])
        .output()
        .expect("docker dry-run json");

    assert!(
        output.status.success(),
        "docker dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture(
        &output.stdout,
        include_str!("fixtures/machine-output/docker_dry_run_v1.json"),
    );
}

#[test]
fn bazel_setup_plan_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .env("BORINGCACHE_BAZEL_STABLE_HOST_ENV", "0")
        .args([
            "bazel",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "bazel-cache",
            "--endpoint-host",
            "host.docker.internal",
            "--port",
            "6001",
            "--no-platform",
            "--no-git",
            "--dry-run",
            "--json",
            "--",
            "bazel",
            "build",
            "//...",
        ])
        .output()
        .expect("bazel dry-run json");

    assert!(
        output.status.success(),
        "bazel dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture_with_placeholders(
        &output.stdout,
        include_str!("fixtures/machine-output/bazel_setup_plan_v1.json"),
        &[home_placeholder()],
    );
}

#[test]
fn gradle_setup_plan_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "gradle",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "gradle-cache",
            "--endpoint-host",
            "host.docker.internal",
            "--port",
            "6001",
            "--no-platform",
            "--no-git",
            "--read-only",
            "--dry-run",
            "--json",
            "--",
            "./gradlew",
            "build",
            "--no-daemon",
        ])
        .output()
        .expect("gradle dry-run json");

    assert!(
        output.status.success(),
        "gradle dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_machine_output_matches_fixture_with_placeholders(
        &output.stdout,
        include_str!("fixtures/machine-output/gradle_setup_plan_v1.json"),
        &[home_placeholder()],
    );
}

#[test]
fn maven_setup_plan_json_matches_v1_contract() {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut command = Command::new(cli_binary());
    apply_test_env(&mut command);
    let output = command
        .current_dir(temp_dir.path())
        .args([
            "maven",
            "--workspace",
            "test-org/test-workspace",
            "--tag",
            "maven-cache",
            "--endpoint-host",
            "host.docker.internal",
            "--port",
            "6001",
            "--no-platform",
            "--no-git",
            "--read-only",
            "--dry-run",
            "--json",
            "--",
            "mvn",
            "install",
            "-DskipTests",
        ])
        .output()
        .expect("maven dry-run json");

    assert!(
        output.status.success(),
        "maven dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut placeholders = workspace_root_placeholders(temp_dir.path());
    placeholders.push(home_placeholder());
    assert_machine_output_matches_fixture_with_placeholders(
        &output.stdout,
        include_str!("fixtures/machine-output/maven_setup_plan_v1.json"),
        &placeholders,
    );
}

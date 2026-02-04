use std::path::PathBuf;
use std::process::Command;

const DUMMY_API_URL: &str = "http://127.0.0.1:65535";

fn cli_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_boringcache")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap()
                .join("target/debug/boringcache")
        })
}

#[test]
fn test_save_argument_parsing() {
    let output = Command::new(cli_binary())
        .args([
            "save",
            "test-org/test-workspace",
            "test-key:/tmp/nonexistent",
        ])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("required"),
        "CLI should accept new format. Got: {stderr}"
    );

    assert!(
        stderr.contains("Skipping: path not found")
            || stderr.contains("No valid paths found")
            || stderr.contains("Failed to")
            || stderr.contains("Error:")
            || stderr.contains("auth")
            || stderr.contains("token"),
        "Should fail with runtime error or show path warnings, not parsing error. Got: {stderr}"
    );
}

#[test]
fn test_save_help_includes_workspace_argument() {
    let output = Command::new(cli_binary())
        .args(["save", "--help"])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("<WORKSPACE>") && stdout.contains("<PATH_TAG_PAIRS>"),
        "Help should show workspace argument and path_tag_pairs argument. Got: {stdout}"
    );
}

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

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
fn test_save_with_missing_paths_continues_processing() {
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file1 = temp_dir.path().join("existing1.txt");
    let test_file2 = temp_dir.path().join("existing2.txt");

    fs::write(&test_file1, "test content 1").expect("Failed to write test file 1");
    fs::write(&test_file2, "test content 2").expect("Failed to write test file 2");

    let nonexistent_path = temp_dir.path().join("nonexistent");
    let another_nonexistent = temp_dir.path().join("also_missing");

    let output = Command::new(cli_binary())
        .args([
            "save",
            "test-workspace/test-app",
            &format!(
                "missing1:{},existing1:{},missing2:{},existing2:{}",
                nonexistent_path.to_string_lossy(),
                test_file1.to_string_lossy(),
                another_nonexistent.to_string_lossy(),
                test_file2.to_string_lossy()
            ),
        ])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("Skipping") && stderr.contains("path not found"),
        "Should show warnings for missing paths. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("nonexistent") || stdout.contains("nonexistent"),
        "Should mention nonexistent path. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("also_missing") || stdout.contains("also_missing"),
        "Should mention also_missing path. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        output.status.success(),
        "Command should remain non-fatal when server connection is unavailable"
    );
}

#[test]
fn test_save_with_all_missing_paths_exits_gracefully() {
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let nonexistent1 = temp_dir.path().join("missing1");
    let nonexistent2 = temp_dir.path().join("missing2");

    let output = Command::new(cli_binary())
        .args([
            "save",
            "test-workspace/test-app",
            &format!(
                "tag1:{},tag2:{}",
                nonexistent1.to_string_lossy(),
                nonexistent2.to_string_lossy()
            ),
        ])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("No valid paths found to save"),
        "Should show no valid paths message. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("missing1") || stdout.contains("missing1"),
        "Should mention missing path. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("missing2") || stdout.contains("missing2"),
        "Should mention missing path. stderr: {}, stdout: {}",
        stderr,
        stdout
    );
}

#[test]
fn test_save_with_only_existing_paths_works_normally() {
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");
    std::env::remove_var("BORINGCACHE_WORKSPACE");

    if let Ok(home_dir) = std::env::var("HOME") {
        let config_path = format!("{}/.boringcache/config.json", home_dir);
        let _ = std::fs::remove_file(&config_path);
    }
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "test content").expect("Failed to write test file");

    let output = Command::new(cli_binary())
        .args([
            "save",
            "test-workspace/test-app",
            &format!("test-tag:{}", test_file.to_str().unwrap()),
        ])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !stderr.contains("Skipping: path not found")
            && !stdout.contains("Skipping: path not found"),
        "Should not warn about missing paths when all exist. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("warning")
            || stderr.contains("auth")
            || stderr.contains("token")
            || stdout.contains("warning"),
        "Should report network/auth failure when saving. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        output.status.success(),
        "Command should remain non-fatal when server connection is unavailable"
    );
}

#[test]
fn test_save_path_expansion_with_missing_tilde_path() {
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");

    let fake_home_path = "~/this/path/definitely/does/not/exist";

    let output = Command::new(cli_binary())
        .args([
            "save",
            "test-workspace/test-app",
            &format!("test-tag:{}", fake_home_path),
        ])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("No valid paths found to save"),
        "Should show no valid paths message. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("expanded from") || stdout.contains("expanded from"),
        "Should show path expansion info. stderr: {}, stdout: {}",
        stderr,
        stdout
    );
}

#[test]
fn test_save_rejects_empty_directory_before_upload() {
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let output = Command::new(cli_binary())
        .args([
            "save",
            "test-workspace/test-app",
            &format!("empty:{}", temp_dir.path().to_string_lossy()),
        ])
        .env("BORINGCACHE_API_URL", DUMMY_API_URL)
        .env("BORINGCACHE_TEST_MODE", "1")
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("no file content to upload")
            || stdout.contains("no file content to upload"),
        "Should fail fast for empty directories. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        output.status.success(),
        "Command should remain non-fatal when attempting to save 0-byte content"
    );
}

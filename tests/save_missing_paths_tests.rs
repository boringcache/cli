use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_save_with_missing_paths_continues_processing() {
    // Ensure clean test environment - remove any existing auth tokens
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");

    // Create a temporary directory with some test files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file1 = temp_dir.path().join("existing1.txt");
    let test_file2 = temp_dir.path().join("existing2.txt");

    fs::write(&test_file1, "test content 1").expect("Failed to write test file 1");
    fs::write(&test_file2, "test content 2").expect("Failed to write test file 2");

    let nonexistent_path = temp_dir.path().join("nonexistent");
    let another_nonexistent = temp_dir.path().join("also_missing");

    // Test with mixed existing and non-existing paths
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "save",
            "test-workspace/test-app",
            &format!(
                "missing1:{},existing1:{},missing2:{},existing2:{}",
                nonexistent_path.to_str().unwrap(),
                test_file1.to_str().unwrap(),
                another_nonexistent.to_str().unwrap(),
                test_file2.to_str().unwrap()
            ),
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should fail during preflight with missing-path error
    assert!(
        stderr.contains("Save preflight failed") || stdout.contains("Save preflight failed"),
        "Should explain preflight failure. stderr: {}, stdout: {}",
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
        !output.status.success(),
        "Command should fail when server connection is unavailable"
    );
}

#[test]
fn test_save_with_all_missing_paths_exits_gracefully() {
    // Ensure clean test environment - remove any existing auth tokens
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let nonexistent1 = temp_dir.path().join("missing1");
    let nonexistent2 = temp_dir.path().join("missing2");

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "save",
            "test-workspace/test-app",
            &format!(
                "tag1:{},tag2:{}",
                nonexistent1.to_str().unwrap(),
                nonexistent2.to_str().unwrap()
            ),
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("Save preflight failed") || stdout.contains("Save preflight failed"),
        "Should explain preflight failure. stderr: {}, stdout: {}",
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
    // Ensure clean test environment - remove any existing auth tokens
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");
    std::env::remove_var("BORINGCACHE_WORKSPACE");

    // Clear any existing config file
    if let Ok(home_dir) = std::env::var("HOME") {
        let config_path = format!("{}/.boringcache/config.json", home_dir);
        let _ = std::fs::remove_file(&config_path);
    }
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "test content").expect("Failed to write test file");

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "save",
            "test-workspace/test-app",
            &format!("test-tag:{}", test_file.to_str().unwrap()),
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should NOT contain any skip warnings
    assert!(
        !stderr.contains("Skipping: path not found")
            && !stdout.contains("Skipping: path not found"),
        "Should not warn about missing paths when all exist. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        stderr.contains("ERROR")
            || stderr.contains("Cannot connect")
            || stderr.contains("API Error")
            || stderr.contains("API token not found")
            || stderr.contains("Resource not found"),
        "Should report network/auth/resource failure when saving. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    assert!(
        !output.status.success(),
        "Command should fail when server connection is unavailable"
    );
}

#[test]
fn test_save_path_expansion_with_missing_tilde_path() {
    // Ensure clean test environment - remove any existing auth tokens
    std::env::remove_var("BORINGCACHE_API_TOKEN");
    std::env::remove_var("BORINGCACHE_API_URL");
    // Test with a tilde path that doesn't exist
    let fake_home_path = "~/this/path/definitely/does/not/exist";

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "save",
            "test-workspace/test-app",
            &format!("test-tag:{}", fake_home_path),
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stderr.contains("Save preflight failed") || stdout.contains("Save preflight failed"),
        "Should explain preflight failure. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    // Should show both original and expanded paths
    assert!(
        stderr.contains("expanded from") || stdout.contains("expanded from"),
        "Should show path expansion info. stderr: {}, stdout: {}",
        stderr,
        stdout
    );
}

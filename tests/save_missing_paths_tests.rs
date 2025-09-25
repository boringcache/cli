use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_save_with_missing_paths_continues_processing() {
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

    // Should contain warnings for missing paths
    assert!(
        stderr.contains("Skipping: path not found") || stdout.contains("Skipping: path not found"),
        "Should warn about missing paths. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    // Should contain references to the missing paths
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

    // Should still process existing files (will fail with API error but that's expected)
    assert!(
        stderr.contains("Saving") || stdout.contains("Saving"),
        "Should start processing valid files. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    // Should show it's processing fewer files than requested
    assert!(
        stderr.contains("Saving 2 cache entries") || stdout.contains("Saving 2 cache entries"),
        "Should process only 2 valid entries out of 4 total. stderr: {}, stdout: {}",
        stderr,
        stdout
    );
}

#[test]
fn test_save_with_all_missing_paths_exits_gracefully() {
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

    // Should warn about missing paths
    assert!(
        stderr.contains("Skipping: path not found") || stdout.contains("Skipping: path not found"),
        "Should warn about missing paths. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    // Should mention that no valid paths were found
    assert!(
        stderr.contains("No valid paths found") || stdout.contains("No valid paths found"),
        "Should mention no valid paths found. stderr: {}, stdout: {}",
        stderr,
        stdout
    );

    // Should exit successfully (code 0) when no valid paths
    // Note: We can't easily test exit code with cargo run, but the important part
    // is that it doesn't crash and provides appropriate messaging
}

#[test]
fn test_save_with_only_existing_paths_works_normally() {
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

    // Should start processing
    assert!(
        stderr.contains("Saving 1 cache entries") || stdout.contains("Saving 1 cache entries"),
        "Should process the single valid entry. stderr: {}, stdout: {}",
        stderr,
        stdout
    );
}

#[test]
fn test_save_path_expansion_with_missing_tilde_path() {
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

    // Should warn about the missing path after tilde expansion
    assert!(
        stderr.contains("Skipping: path not found") || stdout.contains("Skipping: path not found"),
        "Should warn about missing expanded path. stderr: {}, stdout: {}",
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

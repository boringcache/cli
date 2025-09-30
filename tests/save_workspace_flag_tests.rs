use std::process::Command;

#[test]
fn test_save_argument_parsing() {
    // Test new argument format using cargo run (debug mode for speed)
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "save",
            "test-org/test-workspace",
            "/tmp/nonexistent:test-key",
        ])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should not complain about argument parsing
    assert!(
        !stderr.contains("unexpected argument") && !stderr.contains("required"),
        "CLI should accept new format. Got: {stderr}"
    );

    // Should show warning about missing path or fail with API error, not argument parsing error
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
    let output = Command::new("./target/debug/boringcache")
        .args(["save", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("<WORKSPACE>") && stdout.contains("<PATH_TAG_PAIRS>"),
        "Help should show workspace argument and path_tag_pairs argument. Got: {stdout}"
    );
}

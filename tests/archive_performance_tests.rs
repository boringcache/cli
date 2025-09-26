use boring_cache_cli::archive;
use std::fs;
use std::time::Instant;
use tempfile::TempDir;

#[tokio::test]
async fn test_archive_performance_without_scanning() {
    // Create a test directory with some files
    let temp_dir = TempDir::new().unwrap();
    let test_path = temp_dir.path().join("test_dir");
    fs::create_dir(&test_path).unwrap();

    // Create several test files
    for i in 0..50 {
        fs::write(
            test_path.join(format!("file_{}.txt", i)),
            format!("Content for file {}", i),
        )
        .unwrap();
    }

    // Create a subdirectory with more files
    let sub_dir = test_path.join("subdir");
    fs::create_dir(&sub_dir).unwrap();
    for i in 0..25 {
        fs::write(
            sub_dir.join(format!("sub_{}.txt", i)),
            format!("Sub content {}", i),
        )
        .unwrap();
    }

    println!("📁 Created test directory with 75 files");

    // Test with phases (should be fast now - no scanning)
    let start = Instant::now();
    let paths = vec![test_path.to_string_lossy().to_string()];
    let (archive_data, archive_info) = archive::create_archive(&paths, None, true).await.unwrap();
    let elapsed = start.elapsed();

    println!("⚡ Archive created in {:?}", elapsed);
    println!("📊 Archive info:");
    println!("   - Files: {}", archive_info.file_count);
    println!(
        "   - Compressed size: {} bytes",
        archive_info.compressed_size
    );
    println!(
        "   - Uncompressed size: {} bytes",
        archive_info.uncompressed_size
    );
    println!(
        "   - Compression: {}",
        archive_info.compression_backend.name()
    );

    // Test silent version (should be even faster)
    let start = Instant::now();
    let (silent_data, silent_info) = archive::create_archive_silent(&paths, None, false)
        .await
        .unwrap();
    let silent_elapsed = start.elapsed();

    println!("⚡ Silent archive created in {:?}", silent_elapsed);

    // Verify the archive contains the expected files (may include directory entries)
    assert!(
        archive_info.file_count >= 75,
        "Should have at least 75 files, got {}",
        archive_info.file_count
    );
    assert_eq!(
        silent_info.file_count, archive_info.file_count,
        "Silent version should have same file count"
    );
    assert_eq!(
        archive_data.len(),
        silent_data.len(),
        "Archive sizes should match"
    );

    // Performance expectations - should be very fast without scanning
    assert!(
        elapsed.as_millis() < 2000,
        "Archive creation should be under 2 seconds (was {} ms)",
        elapsed.as_millis()
    );
    assert!(
        silent_elapsed.as_millis() < 1000,
        "Silent archive creation should be under 1 second (was {} ms)",
        silent_elapsed.as_millis()
    );

    println!("SUCCESS: Archive performance test passed!");
}

use boring_cache_cli::compression::CompressionBackend;
use std::env;

#[test]
fn test_compression_round_trip() {
    // Use larger test data that will actually benefit from compression
    let test_data = "Hello, World! This is a test of compression backends with some repeated content to make compression effective. ".repeat(50);

    for backend in [CompressionBackend::Lz4, CompressionBackend::Zstd] {
        let compressed = backend.compress(test_data.as_bytes()).unwrap();
        let decompressed = backend.decompress(&compressed).unwrap();

        assert_eq!(test_data.as_bytes(), &decompressed[..]);
        // Compression should reduce size for this repeated test data
        assert!(compressed.len() < test_data.len());
    }
}

#[test]
fn test_compression_backend_names() {
    assert_eq!(CompressionBackend::Lz4.name(), "lz4");
    assert_eq!(CompressionBackend::Zstd.name(), "zstd");
}

#[test]
fn test_environment_variable_selection() {
    // Save original environment state
    let original_compression = env::var("BORINGCACHE_COMPRESSION").ok();
    let original_optimize_for = env::var("BORINGCACHE_OPTIMIZE_FOR").ok();
    let original_network_type = env::var("BORINGCACHE_NETWORK_TYPE").ok();

    // Clear all environment variables that could affect selection
    env::remove_var("BORINGCACHE_COMPRESSION");
    env::remove_var("BORINGCACHE_OPTIMIZE_FOR");
    env::remove_var("BORINGCACHE_NETWORK_TYPE");

    // Test LZ4 selection
    env::set_var("BORINGCACHE_COMPRESSION", "lz4");
    assert_eq!(CompressionBackend::select(), CompressionBackend::Lz4);

    // Test ZSTD selection
    env::set_var("BORINGCACHE_COMPRESSION", "zstd");
    assert_eq!(CompressionBackend::select(), CompressionBackend::Zstd);

    // Test case insensitive
    env::set_var("BORINGCACHE_COMPRESSION", "LZ4");
    assert_eq!(CompressionBackend::select(), CompressionBackend::Lz4);

    env::set_var("BORINGCACHE_COMPRESSION", "ZSTD");
    assert_eq!(CompressionBackend::select(), CompressionBackend::Zstd);

    // Restore original environment state
    match original_compression {
        Some(val) => env::set_var("BORINGCACHE_COMPRESSION", val),
        None => env::remove_var("BORINGCACHE_COMPRESSION"),
    }
    match original_optimize_for {
        Some(val) => env::set_var("BORINGCACHE_OPTIMIZE_FOR", val),
        None => env::remove_var("BORINGCACHE_OPTIMIZE_FOR"),
    }
    match original_network_type {
        Some(val) => env::set_var("BORINGCACHE_NETWORK_TYPE", val),
        None => env::remove_var("BORINGCACHE_NETWORK_TYPE"),
    }
}

#[test]
fn test_upload_optimization_env() {
    // Save original environment state
    let original_compression = env::var("BORINGCACHE_COMPRESSION").ok();
    let original_optimize_for = env::var("BORINGCACHE_OPTIMIZE_FOR").ok();
    let original_network_type = env::var("BORINGCACHE_NETWORK_TYPE").ok();

    // Clear any existing compression overrides
    env::remove_var("BORINGCACHE_COMPRESSION");
    env::remove_var("BORINGCACHE_OPTIMIZE_FOR");
    env::remove_var("BORINGCACHE_NETWORK_TYPE");

    // Set upload optimization
    env::set_var("BORINGCACHE_OPTIMIZE_FOR", "upload");
    assert_eq!(CompressionBackend::select(), CompressionBackend::Lz4);

    // Restore original environment state
    match original_compression {
        Some(val) => env::set_var("BORINGCACHE_COMPRESSION", val),
        None => env::remove_var("BORINGCACHE_COMPRESSION"),
    }
    match original_optimize_for {
        Some(val) => env::set_var("BORINGCACHE_OPTIMIZE_FOR", val),
        None => env::remove_var("BORINGCACHE_OPTIMIZE_FOR"),
    }
    match original_network_type {
        Some(val) => env::set_var("BORINGCACHE_NETWORK_TYPE", val),
        None => env::remove_var("BORINGCACHE_NETWORK_TYPE"),
    }
}

#[test]
fn test_compression_effectiveness() {
    // Test with highly compressible data
    let compressible_data = "A".repeat(1000).into_bytes();

    let lz4_compressed = CompressionBackend::Lz4
        .compress(&compressible_data)
        .unwrap();
    let zstd_compressed = CompressionBackend::Zstd
        .compress(&compressible_data)
        .unwrap();

    // Both should achieve significant compression
    assert!(lz4_compressed.len() < compressible_data.len() / 2);
    assert!(zstd_compressed.len() < compressible_data.len() / 2);

    // ZSTD should generally be better at compression
    assert!(zstd_compressed.len() <= lz4_compressed.len());

    // Verify decompression works correctly
    assert_eq!(
        CompressionBackend::Lz4.decompress(&lz4_compressed).unwrap(),
        compressible_data
    );
    assert_eq!(
        CompressionBackend::Zstd
            .decompress(&zstd_compressed)
            .unwrap(),
        compressible_data
    );
}

#[test]
fn test_random_data_compression() {
    // Test with less compressible (random-like) data
    let random_data: Vec<u8> = (0..1000).map(|i| (i * 17 + 13) as u8).collect();

    let lz4_compressed = CompressionBackend::Lz4.compress(&random_data).unwrap();
    let zstd_compressed = CompressionBackend::Zstd.compress(&random_data).unwrap();

    // Verify decompression works even with less compressible data
    assert_eq!(
        CompressionBackend::Lz4.decompress(&lz4_compressed).unwrap(),
        random_data
    );
    assert_eq!(
        CompressionBackend::Zstd
            .decompress(&zstd_compressed)
            .unwrap(),
        random_data
    );
}

#[test]
fn test_empty_data_compression() {
    let empty_data = b"";

    let lz4_compressed = CompressionBackend::Lz4.compress(empty_data).unwrap();
    let zstd_compressed = CompressionBackend::Zstd.compress(empty_data).unwrap();

    assert_eq!(
        CompressionBackend::Lz4.decompress(&lz4_compressed).unwrap(),
        empty_data
    );
    assert_eq!(
        CompressionBackend::Zstd
            .decompress(&zstd_compressed)
            .unwrap(),
        empty_data
    );
}

#[test]
fn test_single_byte_compression() {
    let single_byte = b"A";

    let lz4_compressed = CompressionBackend::Lz4.compress(single_byte).unwrap();
    let zstd_compressed = CompressionBackend::Zstd.compress(single_byte).unwrap();

    assert_eq!(
        CompressionBackend::Lz4.decompress(&lz4_compressed).unwrap(),
        single_byte
    );
    assert_eq!(
        CompressionBackend::Zstd
            .decompress(&zstd_compressed)
            .unwrap(),
        single_byte
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_cpu_feature_selection() {
    // This test verifies that the CPU feature detection logic compiles
    // and runs without error. The actual selection depends on CPU features.

    // Save original environment state
    let original_compression = env::var("BORINGCACHE_COMPRESSION").ok();
    let original_optimize_for = env::var("BORINGCACHE_OPTIMIZE_FOR").ok();
    let original_network_type = env::var("BORINGCACHE_NETWORK_TYPE").ok();

    // Clear environment variables that might affect selection
    env::remove_var("BORINGCACHE_COMPRESSION");
    env::remove_var("BORINGCACHE_OPTIMIZE_FOR");
    env::remove_var("BORINGCACHE_NETWORK_TYPE");

    let selected = CompressionBackend::select();

    // Should select either LZ4 or ZSTD based on CPU features
    assert!(matches!(
        selected,
        CompressionBackend::Lz4 | CompressionBackend::Zstd
    ));

    // Restore original environment state
    match original_compression {
        Some(val) => env::set_var("BORINGCACHE_COMPRESSION", val),
        None => env::remove_var("BORINGCACHE_COMPRESSION"),
    }
    match original_optimize_for {
        Some(val) => env::set_var("BORINGCACHE_OPTIMIZE_FOR", val),
        None => env::remove_var("BORINGCACHE_OPTIMIZE_FOR"),
    }
    match original_network_type {
        Some(val) => env::set_var("BORINGCACHE_NETWORK_TYPE", val),
        None => env::remove_var("BORINGCACHE_NETWORK_TYPE"),
    }
}

#[test]
fn test_compression_deterministic() {
    let test_data = b"Test data for deterministic compression verification";

    // Compress the same data multiple times
    let lz4_result1 = CompressionBackend::Lz4.compress(test_data).unwrap();
    let lz4_result2 = CompressionBackend::Lz4.compress(test_data).unwrap();

    let zstd_result1 = CompressionBackend::Zstd.compress(test_data).unwrap();
    let zstd_result2 = CompressionBackend::Zstd.compress(test_data).unwrap();

    // Results should be identical (deterministic)
    assert_eq!(lz4_result1, lz4_result2);
    assert_eq!(zstd_result1, zstd_result2);
}

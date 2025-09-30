use anyhow::Result;
use boring_cache_cli::archive::clean_cache_key;
use boring_cache_cli::compression::CompressionBackend;

#[test]
fn test_clean_cache_key() {
    assert_eq!(clean_cache_key("simple-key"), "simple-key");
    assert_eq!(
        clean_cache_key("key-with\n-newlines\r"),
        "key-with-newlines"
    );
    assert_eq!(clean_cache_key("  key-with-spaces  "), "key-with-spaces");
    assert_eq!(clean_cache_key("key-with-trailing---"), "key-with-trailing");
}

#[test]
fn test_compression_backend_names() {
    assert_eq!(CompressionBackend::Lz4.name(), "lz4");
    assert_eq!(CompressionBackend::Zstd.name(), "zstd");
}

#[test]
fn test_compression_round_trip_basic() -> Result<()> {
    let test_data = b"Hello, World! This is test data for compression.";

    for backend in [CompressionBackend::Lz4, CompressionBackend::Zstd] {
        let compressed = backend.compress(test_data)?;
        let decompressed = backend.decompress(&compressed)?;
        assert_eq!(test_data, &decompressed[..]);
    }
    Ok(())
}

#[test]
fn test_compression_selection() {
    // This just tests that selection works without panicking
    let backend = CompressionBackend::select();
    assert!(matches!(
        backend,
        CompressionBackend::Lz4 | CompressionBackend::Zstd
    ));
}

#[test]
fn test_empty_data_compression() -> Result<()> {
    let empty_data = b"";

    let lz4_compressed = CompressionBackend::Lz4.compress(empty_data)?;
    let zstd_compressed = CompressionBackend::Zstd.compress(empty_data)?;

    assert_eq!(
        CompressionBackend::Lz4.decompress(&lz4_compressed)?,
        empty_data
    );
    assert_eq!(
        CompressionBackend::Zstd.decompress(&zstd_compressed)?,
        empty_data
    );

    Ok(())
}

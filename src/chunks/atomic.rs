use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{BufReader as StdBufReader, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};

use super::{
    chunk_cache_paths, generate_chunk_key, load_cached_chunk, recommended_compression_workers,
    write_cached_chunk_metadata, CachedChunkMetadata, MaterializedChunk, CHUNK_COMPRESSION,
    READ_BUFFER_SIZE,
};

const DETECTION_SAMPLE_SIZE: usize = 256 * 1024; // 256 KiB
const MIN_ENTROPY_SAMPLE: usize = 64 * 1024; // 64 KiB
const ENTROPY_THRESHOLD: f64 = 6.5;
const ASCII_RATIO_THRESHOLD: f64 = 0.4;
const MIN_AUTO_ATOMIC_SIZE: u64 = 64 * 1024; // 64 KiB

// Env-driven tuning to control "atomic vs CDC" decisions at scale.
// - BORINGCACHE_FORCE_CDC=true       => Force CDC for all files (except explicit compressed magic)
// - BORINGCACHE_DISABLE_ENTROPY_ATOMIC=true => Only use compressed magic for atomic; disable entropy-based atomic
// - BORINGCACHE_ATOMIC_ONLY_MAGIC=1 => Alias for disabling entropy-based atomic (kept for convenience)
// - BORINGCACHE_MIN_ATOMIC_SIZE_MB=N => Require at least N MiB before considering entropy-based atomic

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStrategy {
    Atomic,
    Cdc,
}

pub fn decide_file_strategy(_path: &Path, _declared_size: u64) -> Result<FileStrategy> {
    // Atomic mode disabled: always stream via CDC to minimize per-entry chunk count variance
    Ok(FileStrategy::Cdc)
}

pub fn get_or_create_atomic_chunk(
    path: &Path,
    expected_size: u64,
    chunk_cache_root: &Path,
    compression_level: i32,
    parallelism: usize,
) -> Result<(MaterializedChunk, String, u64)> {
    let (digest, actual_size) = compute_file_digest(path)?;

    if actual_size != expected_size {
        anyhow::bail!(
            "File size changed during chunking: {} (expected {}, got {})",
            path.display(),
            expected_size,
            actual_size
        );
    }

    let key = generate_chunk_key(&digest);

    if let Ok(Some(cached)) = load_cached_chunk(chunk_cache_root, &key, &digest, actual_size) {
        return Ok((
            MaterializedChunk {
                hash: digest.clone(),
                key,
                path: cached.path,
                compressed_size: cached.compressed_size,
                compressed_hash: cached.compressed_hash,
            },
            digest,
            actual_size,
        ));
    }

    let materialized = compress_atomic_to_cache(
        path,
        chunk_cache_root,
        &key,
        &digest,
        actual_size,
        compression_level,
        parallelism,
    )?;

    Ok((materialized, digest, actual_size))
}

fn matches_compressed_magic(sample: &[u8]) -> bool {
    if let Some(kind) = infer::get(sample) {
        if is_compressed_mime(kind.mime_type()) {
            return true;
        }
    }

    sample.starts_with(&[0x1f, 0x8b])
        || sample.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
        || sample.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])
        || is_tar_archive(sample)
        || is_squashfs_image(sample)
}

fn is_compressed_mime(mime: &str) -> bool {
    matches!(
        mime,
        "application/zip"
            | "application/x-7z-compressed"
            | "application/x-tar"
            | "application/x-xz"
            | "application/gzip"
            | "application/x-gzip"
            | "application/x-bzip2"
            | "application/zstd"
            | "application/x-zstd"
            | "application/x-lzma"
            | "application/x-iso9660-image"
            | "application/vnd.squashfs"
            | "application/x-squashfs"
            | "application/x-cpio"
            | "application/x-apple-diskimage"
    )
}

fn is_tar_archive(sample: &[u8]) -> bool {
    if sample.len() < 512 {
        return false;
    }

    matches!(&sample[257..262], b"ustar" | b"USTAR")
}

fn is_squashfs_image(sample: &[u8]) -> bool {
    if sample.len() < 4 {
        return false;
    }

    matches!(&sample[0..4], b"hsqs" | b"sqsh")
}

fn entropy_threshold_met(sample: &[u8]) -> bool {
    if sample.len() < MIN_ENTROPY_SAMPLE {
        return false;
    }

    let entropy = shannon_entropy(sample);
    let ascii_ratio = compute_ascii_ratio(sample);
    entropy >= ENTROPY_THRESHOLD && ascii_ratio <= ASCII_RATIO_THRESHOLD
}

fn shannon_entropy(sample: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in sample {
        counts[byte as usize] += 1;
    }

    let len = sample.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn compute_ascii_ratio(sample: &[u8]) -> f64 {
    let ascii = sample
        .iter()
        .filter(|&&b| matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
        .count();
    ascii as f64 / sample.len() as f64
}

fn compute_file_digest(path: &Path) -> Result<(String, u64)> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;
    let mut reader = StdBufReader::with_capacity(READ_BUFFER_SIZE, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; READ_BUFFER_SIZE];
    let mut total = 0u64;

    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;

        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
        total += read as u64;
    }

    Ok((format!("blake3:{}", hasher.finalize().to_hex()), total))
}

fn compress_atomic_to_cache(
    source: &Path,
    chunk_cache_root: &Path,
    key: &str,
    digest: &str,
    uncompressed_size: u64,
    compression_level: i32,
    parallelism: usize,
) -> Result<MaterializedChunk> {
    let (data_path, meta_path) = chunk_cache_paths(chunk_cache_root, key)?;
    if let Some(parent) = data_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create chunk cache directory: {}",
                parent.display()
            )
        })?;
    }

    let temp_path = data_path.with_extension("tmp");
    let destination = File::create(&temp_path)
        .with_context(|| format!("Failed to create temp chunk file: {}", temp_path.display()))?;
    let writer = HashingWriter::new(destination);
    let mut encoder = zstd::stream::Encoder::new(writer, compression_level)
        .context("Failed to build streaming zstd encoder")?;

    if parallelism > 1 {
        let _ = encoder.multithread(parallelism.min(32) as u32);
    } else if let Some(workers) =
        recommended_compression_workers(uncompressed_size.min(usize::MAX as u64) as usize)
    {
        let _ = encoder.multithread(workers.clamp(1, 32) as u32);
    }

    let source_file = File::open(source)
        .with_context(|| format!("Failed to open file for compression: {}", source.display()))?;
    let mut reader = StdBufReader::with_capacity(READ_BUFFER_SIZE, source_file);
    let mut buffer = [0u8; READ_BUFFER_SIZE];

    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("Failed to read chunk data: {}", source.display()))?;

        if read == 0 {
            break;
        }

        encoder
            .write_all(&buffer[..read])
            .with_context(|| format!("Failed to stream chunk data: {}", source.display()))?;
    }

    let hashing_writer = encoder
        .finish()
        .context("Failed to finish streaming zstd encoder")?;
    let (mut output_file, compressed_hash, compressed_size) = hashing_writer.finalize();
    output_file
        .flush()
        .with_context(|| format!("Failed to flush chunk file: {}", temp_path.display()))?;
    drop(output_file);

    if let Err(err) = fs::rename(&temp_path, &data_path) {
        if data_path.exists() {
            let _ = fs::remove_file(&data_path);
            fs::rename(&temp_path, &data_path).with_context(|| {
                format!("Failed to finalize chunk file: {}", data_path.display())
            })?;
        } else {
            return Err(err).with_context(|| {
                format!("Failed to finalize chunk file: {}", data_path.display())
            });
        }
    }

    write_cached_chunk_metadata(
        &meta_path,
        &CachedChunkMetadata {
            digest: digest.to_string(),
            compression: Cow::Borrowed(CHUNK_COMPRESSION),
            uncompressed_size,
            compressed_size,
            compressed_hash: compressed_hash.clone(),
        },
    )?;

    Ok(MaterializedChunk {
        hash: digest.to_string(),
        key: key.to_string(),
        path: data_path,
        compressed_size,
        compressed_hash,
    })
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            written: 0,
        }
    }

    fn finalize(self) -> (W, String, u64) {
        let digest = format!("blake3:{}", self.hasher.finalize().to_hex());
        (self.inner, digest, self.written)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        if written > 0 {
            self.hasher.update(&buf[..written]);
            self.written += written as u64;
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn decide_strategy_flags_high_entropy_binary() {
        let temp = tempdir().unwrap();
        let file_path = temp.path().join("random.bin");
        let mut data = vec![0u8; 256 * 1024];
        fastrand::fill(&mut data);
        fs::write(&file_path, &data).unwrap();
        let size = fs::metadata(&file_path).unwrap().len();

        let strategy = decide_file_strategy(&file_path, size).unwrap();
        assert_eq!(strategy, FileStrategy::Cdc);
    }

    #[test]
    fn get_or_create_atomic_chunk_reuses_cached_artifact() {
        let temp = tempdir().unwrap();
        let source_path = temp.path().join("layer.tar");
        let chunk_cache_root = temp.path().join("cache");
        let payload = vec![3u8; 512 * 1024];
        fs::write(&source_path, &payload).unwrap();
        let expected_size = payload.len() as u64;

        let (first, digest, size) =
            get_or_create_atomic_chunk(&source_path, expected_size, &chunk_cache_root, 5, 2)
                .unwrap();

        assert_eq!(size, expected_size);
        assert_eq!(digest, first.hash);
        let (data_path, meta_path) =
            chunk_cache_paths(&chunk_cache_root, &first.key).expect("cache paths");
        assert!(data_path.exists(), "compressed payload missing");
        assert!(meta_path.exists(), "metadata missing");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&data_path).unwrap().permissions();
            perms.set_mode(0o444);
            fs::set_permissions(&data_path, perms).unwrap();
        }

        let (second, digest2, size2) =
            get_or_create_atomic_chunk(&source_path, expected_size, &chunk_cache_root, 5, 1)
                .unwrap();

        assert_eq!(digest2, digest);
        assert_eq!(size2, expected_size);
        assert_eq!(second.path, data_path);
    }
}

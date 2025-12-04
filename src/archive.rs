use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::manifest::{ManifestDraft, ManifestFile};
use crate::platform::resources::SystemResources;
use crate::progress::format_bytes;
use crate::ui;

/// Get adaptive buffer size for tar operations based on system resources
fn get_tar_buffer_size() -> usize {
    let resources = SystemResources::detect();
    match resources.memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => 2 * 1024 * 1024, // 2MB
        crate::platform::resources::MemoryStrategy::Aggressive => 4 * 1024 * 1024, // 4MB
        crate::platform::resources::MemoryStrategy::UltraAggressive => 8 * 1024 * 1024, // 8MB
    }
}

/// Get adaptive read buffer size based on system resources
fn get_read_buffer_size() -> usize {
    let resources = SystemResources::detect();
    match resources.memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => 512 * 1024, // 512KB
        crate::platform::resources::MemoryStrategy::Aggressive => 1024 * 1024, // 1MB
        crate::platform::resources::MemoryStrategy::UltraAggressive => 2 * 1024 * 1024, // 2MB
    }
}

pub struct TarArchiveInfo {
    pub archive_path: tempfile::TempPath,
    pub digest: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub manifest_files: Vec<ManifestFile>,
}

/// Calculate adaptive compression level based on file size and system resources
fn calculate_adaptive_compression_level(total_size: u64, resources: &SystemResources) -> i32 {
    use crate::platform::resources::MemoryStrategy;

    // Base level on file size
    let base_level = if total_size > 500 * 1024 * 1024 {
        0 // Very large files: no compression for speed
    } else if total_size > 100 * 1024 * 1024 {
        1 // Large files: minimal compression
    } else if total_size > 10 * 1024 * 1024 {
        2 // Medium files: light compression
    } else {
        3 // Small files: moderate compression
    };

    // Adjust based on system resources
    match resources.memory_strategy {
        MemoryStrategy::Balanced => {
            // Conservative: prefer speed in constrained environments
            base_level.min(2)
        }
        MemoryStrategy::Aggressive => {
            // Can afford slightly higher compression
            base_level
        }
        MemoryStrategy::UltraAggressive => {
            // High-end system: can use better compression
            if resources.cpu_cores >= 8 && resources.cpu_load_percent < 50.0 {
                (base_level + 1).min(5)
            } else {
                base_level
            }
        }
    }
}

/// Format memory strategy for display
fn format_memory_strategy(strategy: &crate::platform::resources::MemoryStrategy) -> &'static str {
    use crate::platform::resources::MemoryStrategy;
    match strategy {
        MemoryStrategy::Balanced => "balanced",
        MemoryStrategy::Aggressive => "aggressive",
        MemoryStrategy::UltraAggressive => "ultra-aggressive",
    }
}

pub async fn create_tar_archive(
    draft: &ManifestDraft,
    base_path: &str,
    verbose: bool,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>,
) -> Result<TarArchiveInfo> {
    let start_time = Instant::now();
    let temp_file = NamedTempFile::new().context("Failed to create temporary file for archive")?;
    let archive_temp_path = temp_file.into_temp_path();
    let archive_path = archive_temp_path.to_path_buf();

    if verbose {
        ui::info(&format!(
            "  Creating high-performance tar archive ({} files, {})",
            draft.descriptors.len(),
            format_bytes(draft.raw_size)
        ));
    }

    let manifest_files: Vec<ManifestFile> = draft
        .descriptors
        .iter()
        .map(|desc| ManifestFile {
            path: desc.path.clone(),
            entry_type: desc.entry_type,
            size: desc.size,
            mode: desc.mode,
            hash: desc.hash.clone(),
            target: desc.target.clone(),
            state: crate::manifest::EntryState::Present,
        })
        .collect();

    let base_path_owned = base_path.to_owned();
    let archive_path_owned = archive_path.clone();
    let manifest_files_clone = manifest_files.clone();
    let total_size = draft.raw_size;

    // Adaptive compression settings based on system resources and file size
    let resources = SystemResources::detect();
    let compression_level = calculate_adaptive_compression_level(total_size, resources);

    if verbose {
        ui::info(&format!(
            "  Using zstd level {} with {} threads ({})",
            compression_level,
            resources.cpu_cores,
            format_memory_strategy(&resources.memory_strategy)
        ));
    }

    let (compressed_size, digest) = tokio::task::spawn_blocking(move || {
        create_ultra_fast_archive(
            &base_path_owned,
            &archive_path_owned,
            &manifest_files_clone,
            compression_level,
            progress_callback,
        )
    })
    .await
    .context("Archive creation task failed")??;

    let elapsed = start_time.elapsed();
    let throughput = (total_size as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);

    if verbose {
        ui::info(&format!(
            "  Archive created in {:.1}s: {} → {} ({:.1}% ratio, {:.1} MB/s)",
            elapsed.as_secs_f64(),
            format_bytes(total_size),
            format_bytes(compressed_size),
            (compressed_size as f64 / total_size as f64) * 100.0,
            throughput
        ));
    }

    Ok(TarArchiveInfo {
        archive_path: archive_temp_path,
        digest,
        uncompressed_size: total_size,
        compressed_size,
        manifest_files,
    })
}

fn create_ultra_fast_archive(
    base_path: &str,
    archive_path: &Path,
    manifest_files: &[ManifestFile],
    compression_level: i32,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>,
) -> Result<(u64, String)> {
    let base_path_buf = PathBuf::from(base_path);

    let tar_buffer_size = get_tar_buffer_size();
    let output_file = File::create(archive_path)?;
    let writer = BufWriter::with_capacity(tar_buffer_size, output_file);

    let mut encoder = ZstdEncoder::new(writer, compression_level)?;

    // Adaptive threading and window size based on system resources
    let resources = SystemResources::detect();
    let num_threads = resources.cpu_cores.min(resources.max_parallel_chunks) as u32;
    encoder.multithread(num_threads)?;

    // Window size: larger for high-performance systems, smaller for constrained
    let window_log = match resources.memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => 20, // 1MB
        crate::platform::resources::MemoryStrategy::Aggressive => 22, // 4MB
        crate::platform::resources::MemoryStrategy::UltraAggressive => 23, // 8MB
    };
    encoder.window_log(window_log)?;

    // Skip checksum for low compression to maximize speed
    if compression_level <= 1 {
        encoder.include_checksum(false)?;
    }

    let mut tar_builder = tar::Builder::new(encoder);
    tar_builder.mode(tar::HeaderMode::Deterministic);
    tar_builder.follow_symlinks(false);

    let files_processed = Arc::new(AtomicUsize::new(0));
    let total_files = manifest_files.len();

    if base_path_buf.is_file() {
        if let Some(file_name) = base_path_buf.file_name() {
            tar_builder
                .append_path_with_name(&base_path_buf, file_name)
                .context("Failed to add file to tar")?;
        }
    } else if base_path_buf.is_dir() {
        for manifest_file in manifest_files.iter() {
            let full_path = base_path_buf.join(&manifest_file.path);

            if full_path.exists() {
                tar_builder
                    .append_path_with_name(&full_path, &manifest_file.path)
                    .with_context(|| {
                        format!("Failed to add path to tar: {}", manifest_file.path)
                    })?;
            }

            let processed = files_processed.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(ref callback) = progress_callback {
                callback(processed, total_files);
            }
        }
    }

    let encoder = tar_builder.into_inner()?;
    encoder.finish()?;

    let metadata = std::fs::metadata(archive_path)?;
    let compressed_size = metadata.len();
    let digest = calculate_file_digest(archive_path)?;

    Ok((compressed_size, digest))
}

fn calculate_file_digest(path: &Path) -> Result<String> {
    const MMAP_THRESHOLD: u64 = 1024 * 1024;

    let file = File::open(path).context("Failed to open file for digest calculation")?;
    let file_size = file.metadata()?.len();

    let mut hasher = Sha256::new();

    if file_size >= MMAP_THRESHOLD {
        use memmap2::Mmap;
        let mmap = unsafe { Mmap::map(&file)? };
        hasher.update(&mmap);
    } else {
        let read_buffer_size = get_read_buffer_size();
        let mut reader = BufReader::with_capacity(read_buffer_size, file);
        let mut buffer = vec![0; read_buffer_size];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
    }

    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub async fn extract_tar_archive(
    archive_path: &Path,
    target_path: &Path,
    verbose: bool,
    progress_callback: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
) -> Result<()> {
    let start_time = Instant::now();
    let archive_path = archive_path.to_owned();
    let target_path_owned = target_path.to_owned();

    let archive_size = tokio::fs::metadata(&archive_path)
        .await
        .map(|meta| meta.len())
        .unwrap_or_default();

    tokio::fs::create_dir_all(&target_path_owned)
        .await
        .with_context(|| {
            format!(
                "Failed to create target directory {}",
                target_path.display()
            )
        })?;

    if verbose {
        ui::info(&format!(
            "  Extracting archive ({}) to {}",
            format_bytes(archive_size),
            target_path.display()
        ));
    }

    tokio::task::spawn_blocking(move || {
        let file = File::open(&archive_path).context("Failed to open archive for extraction")?;
        let read_buffer = get_read_buffer_size();
        let reader = BufReader::with_capacity(read_buffer, file);
        let decoder = ZstdDecoder::new(reader)?;

        let mut archive = tar::Archive::new(decoder);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(false);
        archive.set_preserve_ownerships(false);

        let mut files_extracted = 0u64;
        let callback_interval = 1000u64;

        for entry in archive.entries()? {
            let mut entry = entry?;
            entry.unpack_in(&target_path_owned)?;

            files_extracted += 1;
            if let Some(ref callback) = &progress_callback {
                if files_extracted.is_multiple_of(callback_interval) {
                    callback(files_extracted);
                }
            }
        }

        if let Some(ref callback) = progress_callback {
            callback(files_extracted);
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Archive extraction task failed")??;

    if verbose {
        let elapsed = start_time.elapsed();
        let throughput = if archive_size > 0 {
            (archive_size as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0)
        } else {
            0.0
        };
        ui::info(&format!(
            "  Extraction completed in {:.1}s ({:.1} MB/s)",
            elapsed.as_secs_f64(),
            throughput
        ));
    }

    Ok(())
}

pub fn should_use_multipart_upload(file_size: u64) -> bool {
    file_size > 5 * 1024 * 1024
}

pub fn calculate_optimal_part_size(file_size: u64) -> u64 {
    const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
    const MAX_PART_SIZE: u64 = 100 * 1024 * 1024;
    const TARGET_PARTS: u64 = 100;

    let ideal_part_size = file_size / TARGET_PARTS;
    ideal_part_size.clamp(MIN_PART_SIZE, MAX_PART_SIZE)
}

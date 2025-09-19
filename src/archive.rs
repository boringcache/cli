use crate::compression::CompressionBackend;
use crate::platform::{MemoryStrategy, SystemResources};
use crate::ui::CleanUI;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Write};
use std::path::Path;
use tar::{Archive as TarArchive, Builder as TarBuilder};
use tokio::fs;
use walkdir::WalkDir;

pub struct ArchiveInfo {
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub file_count: u32,
    pub content_sha256: String,
    pub compression_backend: CompressionBackend,
}

pub async fn create_archive(
    paths: &[String],
    compression_backend: Option<CompressionBackend>,
    verbose: bool,
    platform_fingerprint: Option<String>,
) -> Result<(Vec<u8>, ArchiveInfo)> {
    let mut uncompressed_size = 0u64;
    let mut file_count = 0u32;

    for path_str in paths {
        let path = Path::new(path_str);
        let metadata = fs::symlink_metadata(path)
            .await
            .with_context(|| format!("Failed to stat {path_str}"))?;

        if metadata.is_dir() {
            count_directory_files_with_symlink_option(
                path,
                &mut uncompressed_size,
                &mut file_count,
                false,
            )
            .await?;
        } else {
            uncompressed_size += metadata.len();
            file_count += 1;
        }
    }

    let compression_backend = compression_backend.unwrap_or_else(|| {
        let system = crate::platform::SystemResources::detect();
        CompressionBackend::select_intelligent(uncompressed_size as usize, file_count, system)
    });

    if verbose {
        crate::ui::CleanUI::info(&format!(
            "  Using {} compression",
            compression_backend.name()
        ));
    }

    let paths_clone = paths.to_vec();
    let (compressed_data, compressed_size) =
        tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, u64)> {
            let system = SystemResources::detect();

            let memory_budget = calculate_memory_budget(system);
            let _chunk_size = calculate_optimal_chunk_size(system);
            let buffer_size = (memory_budget / 8).min(4 * 1024 * 1024);

            let mut tar_data = Vec::new();
            {
                let mut buffered_writer = BufWriter::with_capacity(buffer_size, &mut tar_data);
                {
                    let mut tar_builder = TarBuilder::new(&mut buffered_writer);
                    tar_builder.mode(tar::HeaderMode::Deterministic);

                    tar_builder.follow_symlinks(false);

                    for path_str in &paths_clone {
                        let path = std::path::Path::new(path_str);

                        if path.is_dir() {
                            append_dir_contents_streaming(
                                &mut tar_builder,
                                path,
                                _chunk_size,
                                verbose,
                                false,
                            )?;
                        } else {
                            let filename = path
                                .file_name()
                                .unwrap_or(path.as_os_str())
                                .to_string_lossy()
                                .to_string();
                            let mut file = std::fs::File::open(path)?;
                            tar_builder.append_file(&filename, &mut file)?;
                        }
                    }

                    tar_builder.finish()?;
                }
                buffered_writer.flush()?;
            }

            let compressed_data = compression_backend.compress(&tar_data)?;
            let compressed_size = compressed_data.len() as u64;

            Ok((compressed_data, compressed_size))
        })
        .await??;

    let content_sha256 =
        compute_platform_aware_hash(&compressed_data, platform_fingerprint.as_deref());

    Ok((
        compressed_data,
        ArchiveInfo {
            compressed_size,
            uncompressed_size,
            file_count,
            content_sha256,
            compression_backend,
        },
    ))
}

pub async fn extract_archive_with_backend(
    data: &[u8],
    target_path: &str,
    verbose: bool,
    backend: Option<CompressionBackend>,
) -> Result<()> {
    check_available_disk_space(data.len(), target_path)?;

    let temp_dir = tempfile::tempdir()?;
    let extract_dir = temp_dir.path().join("extracted");

    let data_clone = data.to_vec();
    let extract_dir_clone = extract_dir.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let system = SystemResources::detect();
        std::fs::create_dir_all(&extract_dir_clone)?;
        let is_low_memory = std::env::var("CI").is_ok() || system.available_memory_gb < 4.0;
        let is_large_archive = data_clone.len() > 100 * 1024 * 1024;
        if verbose {
            crate::ui::CleanUI::info(&format!("  🔍 Archive: {:.1}GB, Low memory: {}, Large archive: {}", 
                data_clone.len() as f64 / (1024.0 * 1024.0 * 1024.0),
                is_low_memory,
                is_large_archive
            ));
        }
        if is_low_memory || is_large_archive {
            extract_large_archive_streaming(&data_clone, &extract_dir_clone, backend)?;
        } else {
            let decompressed_data = match if let Some(backend) = backend {
                backend.decompress(&data_clone)
            } else {
                CompressionBackend::Zstd.decompress(&data_clone)
                    .or_else(|_| CompressionBackend::Lz4.decompress(&data_clone))
            } {
                Ok(data) => data,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to decompress archive: {}. Archive may be corrupted or incompatible.", e
                    ));
                }
            };
            let buffer_size = if is_low_memory || is_large_archive {
                4 * 1024 * 1024
            } else {
                system.extraction_buffer_size()
            };
            let cursor = std::io::Cursor::new(decompressed_data);
            let buffered = std::io::BufReader::with_capacity(buffer_size, cursor);
            let mut archive = TarArchive::new(buffered);
            archive.set_preserve_permissions(true);
            archive.set_preserve_mtime(false);
            archive.set_unpack_xattrs(false);
            archive.unpack(&extract_dir_clone).with_context(|| {
                format!("Failed to extract archive to {}", extract_dir_clone.display())
            })?;
        }
        Ok(())
    }).await.with_context(|| "Archive extraction task failed")??;

    move_extracted_contents(&extract_dir, target_path, verbose).await?;

    Ok(())
}

fn check_available_disk_space(compressed_size: usize, target_path: &str) -> Result<()> {
    use std::path::Path;

    let target_path_obj = Path::new(target_path);
    let parent_dir = target_path_obj.parent().unwrap_or(target_path_obj);

    if let Ok(available_bytes) = get_available_space(parent_dir) {
        let compressed_size_gb = compressed_size as f64 / (1024.0 * 1024.0 * 1024.0);
        let available_gb = available_bytes as f64 / (1024.0 * 1024.0 * 1024.0);

        let estimated_decompressed_gb = compressed_size_gb * 3.5;

        let required_space_gb = estimated_decompressed_gb + 1.0;

        if available_gb < required_space_gb {
            return Err(anyhow::anyhow!(
                "Insufficient disk space for extraction:\n  \
                 • Archive size: {:.1}GB (compressed)\n  \
                 • Estimated size after extraction: {:.1}GB\n  \
                 • Space required (with buffer): {:.1}GB\n  \
                 • Space available: {:.1}GB\n  \
                 • Please free up at least {:.1}GB of disk space",
                compressed_size_gb,
                estimated_decompressed_gb,
                required_space_gb,
                available_gb,
                required_space_gb - available_gb
            ));
        }

        if available_gb < required_space_gb + 2.0 {
            CleanUI::info("⚠️ Low disk space warning:");
            CleanUI::info(&format!(
                "Available: {available_gb:.1}GB, Required: {required_space_gb:.1}GB"
            ));
            CleanUI::info("Consider freeing up space for better performance");
        }
    }

    Ok(())
}

fn get_available_space(path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem;

        let path_str = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
        let c_path = CString::new(path_str)?;

        unsafe {
            let mut statvfs: libc::statvfs = mem::zeroed();
            if libc::statvfs(c_path.as_ptr(), &mut statvfs) == 0 {
                #[cfg(target_os = "linux")]
                {
                    Ok(statvfs.f_bavail * statvfs.f_frsize)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Ok(u64::from(statvfs.f_bavail) * statvfs.f_frsize)
                }
            } else {
                Err(anyhow::anyhow!("Failed to get filesystem stats"))
            }
        }
    }

    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let path_wide: Vec<u16> = OsStr::new(path.to_str().unwrap_or("."))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free_bytes = 0u64;
        let result = unsafe {
            winapi::um::fileapi::GetDiskFreeSpaceExW(
                path_wide.as_ptr(),
                &mut free_bytes as *mut u64 as *mut _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if result != 0 {
            Ok(free_bytes)
        } else {
            Err(anyhow::anyhow!("Failed to get disk space on Windows"))
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(1024 * 1024 * 1024)
    }
}

#[allow(dead_code)]
async fn count_directory_files(
    src: &Path,
    uncompressed_size: &mut u64,
    file_count: &mut u32,
) -> Result<()> {
    count_directory_files_with_symlink_option(src, uncompressed_size, file_count, false).await
}

async fn count_directory_files_with_symlink_option(
    src: &Path,
    uncompressed_size: &mut u64,
    file_count: &mut u32,
    follow_symlinks: bool,
) -> Result<()> {
    for entry in WalkDir::new(src).follow_links(follow_symlinks) {
        let entry = entry?;
        let path = entry.path();
        let relative_path = path.strip_prefix(src)?;

        let path_str = relative_path.to_string_lossy();
        if should_skip_path(&path_str) {
            continue;
        }

        if entry.file_type().is_file() || (follow_symlinks && entry.file_type().is_symlink()) {
            let metadata = entry.metadata()?;
            *uncompressed_size += metadata.len();
            *file_count += 1;
        }
    }
    Ok(())
}

async fn move_extracted_contents(
    extract_dir: &Path,
    target_path: &str,
    verbose: bool,
) -> Result<()> {
    let mut entries = fs::read_dir(extract_dir).await?;
    let mut extracted_items = Vec::new();

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        extracted_items.push((name.clone(), entry.path()));
    }

    if verbose {
        let names: Vec<String> = extracted_items
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        CleanUI::info(&format!("📂 Extracted contains: {}", names.join(", ")));
    }

    if extracted_items.is_empty() {
        anyhow::bail!("No files found in extracted archive");
    }

    let target = if target_path == "." {
        Path::new(".")
    } else {
        fs::create_dir_all(target_path).await?;
        Path::new(target_path)
    };

    let system = SystemResources::detect();

    if system.should_use_parallel_extraction() && extracted_items.len() > 1 {
        use futures_util::stream::FuturesUnordered;
        let mut futures = FuturesUnordered::new();

        for (item_name, src_path) in extracted_items.into_iter() {
            let dest_path = target.join(&item_name);
            let src_path_clone = src_path.clone();
            let item_name_clone = item_name.clone();

            let future = async move {
                move_single_item(&src_path_clone, &dest_path, &item_name_clone, verbose).await
            };
            futures.push(future);
        }

        while let Some(result) = futures_util::StreamExt::next(&mut futures).await {
            result?;
        }
    } else {
        for (item_name, src_path) in &extracted_items {
            let dest_path = target.join(item_name);
            move_single_item(src_path, &dest_path, item_name, verbose).await?;
        }
    }

    Ok(())
}

async fn move_single_item(
    src_path: &Path,
    dest_path: &Path,
    item_name: &str,
    verbose: bool,
) -> Result<()> {
    if dest_path.exists() {
        let temp_path = dest_path.with_extension(format!("boringcache_tmp_{}", std::process::id()));

        if tokio::fs::rename(&dest_path, &temp_path).await.is_ok() {
            if tokio::fs::rename(src_path, &dest_path).await.is_ok() {
                tokio::spawn(async move {
                    let _ = tokio::fs::remove_dir_all(&temp_path).await;
                });
                if verbose {
                    CleanUI::info(&format!("✅ Restored: {item_name}"));
                }
                return Ok(());
            }
            let _ = tokio::fs::rename(&temp_path, &dest_path).await;
        }

        remove_path_aggressively(dest_path).await?;
    }

    if tokio::fs::rename(src_path, &dest_path).await.is_ok() {
        if verbose {
            CleanUI::info(&format!("✅ Restored: {item_name}"));
        }
        return Ok(());
    }

    move_recursively(src_path, dest_path).await?;

    if verbose {
        CleanUI::info(&format!("✅ Restored: {item_name}"));
    }

    Ok(())
}

async fn remove_path_aggressively(path: &Path) -> Result<()> {
    if let Ok(metadata) = tokio::fs::metadata(path).await {
        if metadata.is_dir() {
            let temp_path = path.with_extension(format!("rm_{}", std::process::id()));
            if tokio::fs::rename(path, &temp_path).await.is_ok() {
                tokio::task::spawn_blocking(move || {
                    let _ = std::fs::remove_dir_all(&temp_path);
                });
                return Ok(());
            }
            let path_clone = path.to_path_buf();
            tokio::task::spawn_blocking(move || std::fs::remove_dir_all(&path_clone)).await??;
        } else {
            tokio::fs::remove_file(path).await?;
        }
    }
    Ok(())
}

async fn move_recursively(src: &Path, dest: &Path) -> Result<()> {
    let metadata = fs::metadata(src).await?;

    if metadata.is_dir() {
        fs::create_dir_all(dest).await?;

        if dest.parent().map(|p| p.exists()).unwrap_or(true) {
            if let Ok(()) = tokio::fs::rename(src, dest).await {
                return Ok(());
            }
        }

        let mut entries = fs::read_dir(src).await?;
        while let Some(entry) = entries.next_entry().await? {
            let src_path = entry.path();
            let dest_path = dest.join(entry.file_name());
            Box::pin(move_recursively(&src_path, &dest_path)).await?;
        }
    } else {
        fs::create_dir_all(dest.parent().unwrap()).await?;
        if tokio::fs::rename(src, dest).await.is_err() {
            fs::copy(src, dest).await?;
        }
    }

    Ok(())
}

fn compute_platform_aware_hash(data: &[u8], platform_fingerprint: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);

    if let Some(platform_fp) = platform_fingerprint {
        hasher.update(b"platform:");
        hasher.update(platform_fp.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

pub fn clean_cache_key(key: &str) -> String {
    let cleaned = key.replace(['\r', '\n'], "");
    let cleaned = cleaned.trim_end_matches(|c: char| c.is_whitespace() || c == '-');
    cleaned.trim().to_string()
}

fn should_skip_path(path: &str) -> bool {
    let skip_patterns = [
        ".git/",
        ".svn/",
        ".hg/",
        ".bzr/",
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        "*.tmp",
        "*.temp",
        "~*",
        ".#*",
        "*.log",
        "npm-debug.log*",
        "yarn-debug.log*",
        "yarn-error.log*",
        ".cache/",
        "tmp/",
        "temp/",
    ];

    for pattern in skip_patterns.iter() {
        if pattern.ends_with('/') {
            if path.starts_with(pattern) || path.contains(&format!("/{pattern}")) {
                return true;
            }
        } else if pattern.contains('*') {
            let pattern = pattern.replace('*', "");
            if path.ends_with(&pattern) {
                return true;
            }
        } else if path.ends_with(pattern) || path == *pattern {
            return true;
        }
    }
    false
}

fn append_dir_contents_streaming<W: Write>(
    tar_builder: &mut TarBuilder<W>,
    source_path: &Path,
    _chunk_size: usize,
    verbose: bool,
    _should_follow_symlinks: bool,
) -> Result<()> {
    use std::fs::File;

    for entry in WalkDir::new(source_path) {
        let entry =
            entry.with_context(|| format!("Failed to read directory entry in {source_path:?}"))?;
        let path = entry.path();
        let relative_path = path
            .strip_prefix(source_path)
            .with_context(|| format!("Failed to get relative path for {path:?}"))?;

        if relative_path.to_string_lossy().is_empty() {
            continue;
        }

        let path_str = relative_path.to_string_lossy();
        if should_skip_path(&path_str) {
            continue;
        }

        let archive_path = relative_path.to_string_lossy().to_string();

        if entry.file_type().is_dir() {
            tar_builder
                .append_dir(&archive_path, path)
                .with_context(|| format!("Failed to add directory {path:?} to archive"))?;
        } else if entry.file_type().is_file() {
            let mut file =
                File::open(path).with_context(|| format!("Failed to open file {path:?}"))?;

            tar_builder
                .append_file(&archive_path, &mut file)
                .with_context(|| format!("Failed to add file {path:?} to archive"))?;
        } else if entry.file_type().is_symlink() {
            let link_target = std::fs::read_link(path)
                .with_context(|| format!("Failed to read symlink target for {path:?}"))?;
            let mut header = tar::Header::new_gnu();
            header.set_path(&archive_path)?;
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_cksum();

            tar_builder
                .append_link(&mut header, &archive_path, &link_target)
                .with_context(|| {
                    format!("Failed to add symlink {path:?} -> {link_target:?} to archive")
                })?;
        }
    }

    if verbose {
        CleanUI::info(&format!("📁 Archived directory: {}", source_path.display()));
    }

    Ok(())
}

fn calculate_memory_budget(system: &SystemResources) -> usize {
    let available_bytes = (system.available_memory_gb * 1024.0 * 1024.0 * 1024.0) as usize;

    match system.memory_strategy {
        MemoryStrategy::UltraAggressive => (available_bytes / 4).min(1024 * 1024 * 1024),
        MemoryStrategy::Aggressive => (available_bytes / 7).min(512 * 1024 * 1024),
        MemoryStrategy::Balanced => {
            let budget = available_bytes / 10;
            if available_bytes < 512 * 1024 * 1024 {
                32 * 1024 * 1024
            } else if available_bytes < 2 * 1024 * 1024 * 1024 {
                64 * 1024 * 1024
            } else {
                budget.min(256 * 1024 * 1024)
            }
        }
    }
}

fn calculate_optimal_chunk_size(system: &SystemResources) -> usize {
    let base_chunk = 64 * 1024;

    match system.memory_strategy {
        MemoryStrategy::UltraAggressive => base_chunk * 4,
        MemoryStrategy::Aggressive => base_chunk * 2,
        MemoryStrategy::Balanced => base_chunk,
    }
}

fn extract_large_archive_streaming(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
    backend: Option<CompressionBackend>,
) -> Result<()> {
    use std::io::{BufReader, Read};

    let decompressed_stream: Box<dyn Read> = if let Some(backend) = backend {
        match backend {
            CompressionBackend::Zstd => Box::new(zstd::Decoder::new(compressed_data)?),
            CompressionBackend::Lz4 => {
                return extract_lz4_archive_chunked(compressed_data, extract_dir);
            }
        }
    } else {
        match zstd::Decoder::new(compressed_data) {
            Ok(decoder) => Box::new(decoder),
            Err(_) => {
                return extract_lz4_archive_chunked(compressed_data, extract_dir);
            }
        }
    };

    let buffered_stream = BufReader::with_capacity(1024 * 1024, decompressed_stream);
    let mut archive = TarArchive::new(buffered_stream);

    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

    archive.unpack(extract_dir)?;
    Ok(())
}

fn extract_lz4_archive_chunked(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
) -> Result<()> {
    let system = SystemResources::detect();
    let archive_size_gb = compressed_data.len() as f64 / (1024.0 * 1024.0 * 1024.0);

    let use_in_memory = match system.memory_strategy {
        MemoryStrategy::UltraAggressive => archive_size_gb < 2.0,
        MemoryStrategy::Aggressive => archive_size_gb < 1.0,
        MemoryStrategy::Balanced => archive_size_gb < 0.5,
    };

    if use_in_memory {
        let decompressed = CompressionBackend::Lz4.decompress(compressed_data)?;
        let cursor = std::io::Cursor::new(decompressed);
        let buffered = std::io::BufReader::with_capacity(system.extraction_buffer_size(), cursor);
        let mut archive = TarArchive::new(buffered);

        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(false);
        archive.set_unpack_xattrs(false);
        archive.unpack(extract_dir)?;
        Ok(())
    } else {
        extract_lz4_via_filesystem(compressed_data, extract_dir, system)
    }
}

fn extract_lz4_via_filesystem(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
    system: &SystemResources,
) -> Result<()> {
    try_streaming_lz4_extraction(compressed_data, extract_dir, system)?;

    Ok(())
}

fn try_streaming_lz4_extraction(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
    system: &SystemResources,
) -> Result<()> {
    if is_lz4_frame_format(compressed_data) {
        stream_decompress_lz4_frame(compressed_data, extract_dir, system)
    } else {
        decompress_lz4_block_optimized(compressed_data, extract_dir, system)
    }
}

fn is_lz4_frame_format(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..4] == [0x04, 0x22, 0x4D, 0x18]
}

fn stream_decompress_lz4_frame(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
    system: &SystemResources,
) -> Result<()> {
    use std::io::{BufReader, Cursor};

    let cursor = Cursor::new(compressed_data);
    let lz4_decoder = lz4_flex::frame::FrameDecoder::new(cursor);
    let buffered_decoder = BufReader::with_capacity(system.extraction_buffer_size(), lz4_decoder);

    let mut archive = TarArchive::new(buffered_decoder);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

    archive
        .unpack(extract_dir)
        .context("Failed to extract TAR from LZ4 stream")?;
    Ok(())
}

fn decompress_lz4_block_optimized(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
    system: &SystemResources,
) -> Result<()> {
    let compressed_size_gb = compressed_data.len() as f64 / (1024.0 * 1024.0 * 1024.0);

    if compressed_size_gb > 1.0 {
        let estimated_decompressed_size = (compressed_data.len() as f64 * 3.5) as u64;
        let available_memory_bytes = (system.available_memory_gb * 1024.0 * 1024.0 * 1024.0) as u64;

        if estimated_decompressed_size > available_memory_bytes / 2 {
            return Err(anyhow::anyhow!(
                "LZ4 block format archive too large for available memory:\n  \
                 • Compressed size: {:.1}GB\n  \
                 • Estimated decompressed size: {:.1}GB\n  \
                 • Available memory: {:.1}GB\n  \
                 • Memory required: {:.1}GB (50% of available)\n  \
                 Consider freeing up memory or using a machine with more RAM for large Swift archives.", 
                compressed_size_gb,
                estimated_decompressed_size as f64 / (1024.0 * 1024.0 * 1024.0),
                system.available_memory_gb,
                estimated_decompressed_size as f64 / (1024.0 * 1024.0 * 1024.0)
            ));
        }
    }

    try_memory_lz4_decompression(compressed_data, extract_dir, system).with_context(|| {
        format!(
            "LZ4 decompression failed for {:.1}GB archive. This could be due to:\n  \
             • Insufficient disk space (need ~{:.1}GB)\n  \
             • Insufficient memory (need ~{:.1}GB)\n  \
             • Corrupted archive data\n  \
             • Filesystem permissions",
            compressed_size_gb,
            compressed_size_gb * 3.5,
            compressed_size_gb * 2.0
        )
    })
}

fn try_memory_lz4_decompression(
    compressed_data: &[u8],
    extract_dir: &std::path::Path,
    system: &SystemResources,
) -> Result<()> {
    use std::io::{BufReader, Cursor};

    let decompressed_data = lz4_flex::decompress_size_prepended(compressed_data)
        .context("Failed to decompress LZ4 block in memory")?;

    let cursor = Cursor::new(decompressed_data);
    let buffered = BufReader::with_capacity(system.extraction_buffer_size(), cursor);
    let mut archive = TarArchive::new(buffered);

    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);
    archive.unpack(extract_dir)?;

    Ok(())
}

pub fn extract_tar(tar_path: &std::path::Path, extract_dir: &std::path::Path) -> Result<()> {
    let tar_file = std::fs::File::open(tar_path)
        .with_context(|| format!("Failed to open tar file: {}", tar_path.display()))?;

    let mut archive = TarArchive::new(tar_file);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

    archive.unpack(extract_dir).with_context(|| {
        format!(
            "Failed to extract tar archive to: {}",
            extract_dir.display()
        )
    })?;

    Ok(())
}

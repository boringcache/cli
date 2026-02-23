use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::manifest::{ManifestDraft, ManifestFile};
use crate::platform::resources::{MemoryStrategy, SystemResources};
use crate::progress::format_bytes;
use crate::ui;

pub struct TarArchiveInfo {
    pub archive_path: tempfile::TempPath,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub manifest_files: Vec<ManifestFile>,
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
            executable: desc.executable,
            hash: desc.hash.clone(),
            target: desc.target.clone(),
            state: crate::manifest::EntryState::Present,
        })
        .collect();

    let base_path_owned = base_path.to_owned();
    let archive_path_owned = archive_path.clone();
    let manifest_files_clone = manifest_files.clone();
    let total_size = draft.raw_size;

    let resources = SystemResources::detect();
    let compression_level = select_compression_level(total_size, resources);

    if verbose {
        ui::info(&format!(
            "  Using zstd level {} with {} threads ({})",
            compression_level,
            resources.cpu_cores,
            format_strategy(&resources.memory_strategy)
        ));
    }

    let compressed_size = tokio::task::spawn_blocking(move || {
        write_archive(
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
        uncompressed_size: total_size,
        compressed_size,
        manifest_files,
    })
}

fn write_archive(
    base_path: &str,
    archive_path: &Path,
    manifest_files: &[ManifestFile],
    compression_level: i32,
    progress_callback: Option<Box<dyn Fn(usize, usize) + Send>>,
) -> Result<u64> {
    let base_path_buf = PathBuf::from(base_path);
    let resources = SystemResources::detect();

    let output_file = File::create(archive_path)?;
    let writer = BufWriter::with_capacity(tar_buffer_size(resources), output_file);

    let mut encoder = ZstdEncoder::new(writer, compression_level)?;
    encoder.multithread(resources.cpu_cores.min(resources.max_parallel_chunks) as u32)?;
    encoder.window_log(window_log(resources))?;

    encoder.include_checksum(true)?;

    let mut tar_builder = tar::Builder::new(encoder);
    tar_builder.mode(tar::HeaderMode::Complete);
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

    Ok(fs::metadata(archive_path)?.len())
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

    let resources = SystemResources::detect();
    let extraction_config = ExtractionConfig::from_resources(resources, archive_size);

    if verbose {
        ui::info(&format!(
            "  Extracting archive ({}) to {} ({} workers, {})",
            format_bytes(archive_size),
            target_path.display(),
            extraction_config.worker_count,
            format_strategy(&resources.memory_strategy)
        ));
    }

    tokio::task::spawn_blocking(move || {
        extract_parallel(
            &archive_path,
            &target_path_owned,
            &extraction_config,
            progress_callback,
        )
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

struct ExtractionConfig {
    worker_count: usize,
    queue_size: usize,
    read_buffer_size: usize,
    write_buffer_size: usize,
    small_file_threshold: u64,
}

impl ExtractionConfig {
    fn from_resources(resources: &SystemResources, archive_size: u64) -> Self {
        let base_workers = match resources.memory_strategy {
            MemoryStrategy::Balanced => 2,
            MemoryStrategy::Aggressive => 4,
            MemoryStrategy::UltraAggressive => 8,
        };

        let cpu_adjusted = base_workers.min(resources.cpu_cores).max(1);

        let load_adjusted = if resources.cpu_load_percent > 80.0 {
            (cpu_adjusted / 2).max(1)
        } else if resources.cpu_load_percent > 50.0 {
            (cpu_adjusted * 3 / 4).max(1)
        } else {
            cpu_adjusted
        };

        let size_adjusted = if archive_size < 10 * 1024 * 1024 {
            load_adjusted.min(2)
        } else if archive_size < 100 * 1024 * 1024 {
            load_adjusted.min(4)
        } else {
            load_adjusted
        };

        let queue_size = match resources.memory_strategy {
            MemoryStrategy::Balanced => size_adjusted * 64,
            MemoryStrategy::Aggressive => size_adjusted * 128,
            MemoryStrategy::UltraAggressive => size_adjusted * 256,
        };

        let read_buffer_size = match resources.memory_strategy {
            MemoryStrategy::Balanced => 1024 * 1024,
            MemoryStrategy::Aggressive => 2 * 1024 * 1024,
            MemoryStrategy::UltraAggressive => 4 * 1024 * 1024,
        };

        let write_buffer_size = match resources.memory_strategy {
            MemoryStrategy::Balanced => 64 * 1024,
            MemoryStrategy::Aggressive => 128 * 1024,
            MemoryStrategy::UltraAggressive => 256 * 1024,
        };

        let small_file_threshold = match resources.memory_strategy {
            MemoryStrategy::Balanced => 32 * 1024,
            MemoryStrategy::Aggressive => 64 * 1024,
            MemoryStrategy::UltraAggressive => 128 * 1024,
        };

        Self {
            worker_count: size_adjusted,
            queue_size,
            read_buffer_size,
            write_buffer_size,
            small_file_threshold,
        }
    }
}

enum ExtractJob {
    Directory {
        path: PathBuf,
        mode: Option<u32>,
    },
    File {
        path: PathBuf,
        data: Vec<u8>,
        mode: Option<u32>,
        mtime: Option<u64>,
    },
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
    LargeFile {
        path: PathBuf,
        mode: Option<u32>,
        mtime: Option<u64>,
    },
}

fn extract_parallel(
    archive_path: &Path,
    target_path: &Path,
    config: &ExtractionConfig,
    progress_callback: Option<std::sync::Arc<dyn Fn(u64) + Send + Sync>>,
) -> Result<()> {
    use std::sync::mpsc;
    use std::thread;

    let file = File::open(archive_path).context("Failed to open archive for extraction")?;
    let reader = BufReader::with_capacity(config.read_buffer_size, file);
    let decoder = ZstdDecoder::new(reader)?;

    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(false);
    archive.set_preserve_ownerships(false);

    let (job_tx, job_rx) = mpsc::sync_channel::<ExtractJob>(config.queue_size);
    let job_rx = std::sync::Arc::new(std::sync::Mutex::new(job_rx));

    let files_extracted = Arc::new(AtomicUsize::new(0));
    let target_path = target_path.to_owned();

    let workers: Vec<_> = (0..config.worker_count)
        .map(|_| {
            let rx = job_rx.clone();
            let target = target_path.clone();
            let counter = files_extracted.clone();
            let callback = progress_callback.clone();
            thread::spawn(move || loop {
                let job = {
                    let guard = rx.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.recv()
                };

                match job {
                    Ok(ExtractJob::Directory { path, mode }) => {
                        let full_path = target.join(&path);
                        if let Err(e) = fs::create_dir_all(&full_path) {
                            if e.kind() != std::io::ErrorKind::AlreadyExists {
                                log::warn!("Failed to create directory {:?}: {}", full_path, e);
                            }
                        }
                        if let Some(m) = mode {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ =
                                    fs::set_permissions(&full_path, fs::Permissions::from_mode(m));
                            }
                            let _ = m;
                        }
                        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(ref cb) = callback {
                            if count.is_multiple_of(1000) {
                                cb(count as u64);
                            }
                        }
                    }
                    Ok(ExtractJob::File {
                        path,
                        data,
                        mode,
                        mtime,
                    }) => {
                        let full_path = target.join(&path);
                        if let Some(parent) = full_path.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        if let Err(e) = write_file(&full_path, &data, mode, mtime) {
                            log::warn!("Failed to write file {:?}: {}", full_path, e);
                        }
                        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(ref cb) = callback {
                            if count.is_multiple_of(1000) {
                                cb(count as u64);
                            }
                        }
                    }
                    Ok(ExtractJob::Symlink {
                        path,
                        target: link_target,
                    }) => {
                        let full_path = target.join(&path);
                        if let Some(parent) = full_path.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        #[cfg(unix)]
                        {
                            let _ = std::os::unix::fs::symlink(&link_target, &full_path);
                        }
                        #[cfg(windows)]
                        {
                            if link_target.is_dir() {
                                let _ = std::os::windows::fs::symlink_dir(&link_target, &full_path);
                            } else {
                                let _ =
                                    std::os::windows::fs::symlink_file(&link_target, &full_path);
                            }
                        }
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(ExtractJob::LargeFile { path, mode, mtime }) => {
                        let full_path = target.join(&path);
                        if let Some(parent) = full_path.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        apply_file_metadata(&full_path, mode, mtime);
                        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(ref cb) = callback {
                            if count.is_multiple_of(1000) {
                                cb(count as u64);
                            }
                        }
                    }
                    Err(_) => break,
                }
            })
        })
        .collect();

    let mut directories = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let header = entry.header();
        let entry_type = header.entry_type();

        #[cfg(unix)]
        let mode = header.mode().ok();
        #[cfg(not(unix))]
        let mode: Option<u32> = None;

        let mtime = header.mtime().ok();

        match entry_type {
            tar::EntryType::Directory => {
                directories.push(ExtractJob::Directory {
                    path: path.clone(),
                    mode,
                });
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let size = entry.size();

                if size <= config.small_file_threshold {
                    let mut data = Vec::with_capacity(size as usize);
                    std::io::Read::read_to_end(&mut entry, &mut data)?;
                    job_tx
                        .send(ExtractJob::File {
                            path,
                            data,
                            mode,
                            mtime,
                        })
                        .ok();
                } else {
                    let full_path = target_path.join(&path);
                    if let Some(parent) = full_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let file = File::create(&full_path)?;
                    let mut writer = BufWriter::with_capacity(config.write_buffer_size, file);
                    std::io::copy(&mut entry, &mut writer)?;
                    drop(writer);

                    job_tx
                        .send(ExtractJob::LargeFile { path, mode, mtime })
                        .ok();
                }
            }
            tar::EntryType::Symlink | tar::EntryType::Link => {
                if let Ok(Some(link_target)) = entry.link_name() {
                    job_tx
                        .send(ExtractJob::Symlink {
                            path,
                            target: link_target.into_owned(),
                        })
                        .ok();
                }
            }
            _ => {
                entry.unpack_in(&target_path)?;
            }
        }
    }

    for dir_job in directories {
        job_tx.send(dir_job).ok();
    }

    drop(job_tx);

    for worker in workers {
        let _ = worker.join();
    }

    if let Some(ref callback) = progress_callback {
        callback(files_extracted.load(Ordering::Relaxed) as u64);
    }

    Ok(())
}

fn write_file(path: &Path, data: &[u8], mode: Option<u32>, mtime: Option<u64>) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    std::io::Write::write_all(&mut writer, data)?;
    drop(writer);

    apply_file_metadata(path, mode, mtime);
    Ok(())
}

fn apply_file_metadata(path: &Path, mode: Option<u32>, mtime: Option<u64>) {
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(m));
    }

    #[cfg(not(unix))]
    let _ = mode;

    if let Some(mtime_secs) = mtime {
        let mtime = filetime::FileTime::from_unix_time(mtime_secs as i64, 0);
        let _ = filetime::set_file_mtime(path, mtime);
    }
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

fn select_compression_level(total_size: u64, resources: &SystemResources) -> i32 {
    let base_level = if total_size > 500 * 1024 * 1024 {
        3
    } else if total_size > 100 * 1024 * 1024 {
        4
    } else if total_size > 10 * 1024 * 1024 {
        5
    } else {
        6
    };

    match resources.memory_strategy {
        MemoryStrategy::Balanced => base_level.min(4),
        MemoryStrategy::Aggressive => base_level,
        MemoryStrategy::UltraAggressive => {
            if resources.cpu_cores >= 8 && resources.cpu_load_percent < 50.0 {
                (base_level + 1).min(9)
            } else {
                base_level
            }
        }
    }
}

fn tar_buffer_size(resources: &SystemResources) -> usize {
    match resources.memory_strategy {
        MemoryStrategy::Balanced => 2 * 1024 * 1024,
        MemoryStrategy::Aggressive => 4 * 1024 * 1024,
        MemoryStrategy::UltraAggressive => 8 * 1024 * 1024,
    }
}

fn window_log(resources: &SystemResources) -> u32 {
    match resources.memory_strategy {
        MemoryStrategy::Balanced => 20,
        MemoryStrategy::Aggressive => 22,
        MemoryStrategy::UltraAggressive => 23,
    }
}

fn format_strategy(strategy: &MemoryStrategy) -> &'static str {
    match strategy {
        MemoryStrategy::Balanced => "balanced",
        MemoryStrategy::Aggressive => "aggressive",
        MemoryStrategy::UltraAggressive => "ultra-aggressive",
    }
}

pub fn encrypt_archive(
    archive_path: &Path,
    recipient: &age::x25519::Recipient,
) -> Result<tempfile::TempPath> {
    let start_time = Instant::now();
    let input_size = fs::metadata(archive_path)?.len();

    let temp_file =
        NamedTempFile::new().context("Failed to create temporary file for encrypted archive")?;
    let encrypted_path = temp_file.into_temp_path();

    let input_file = File::open(archive_path).context("Failed to open archive for encryption")?;
    let input_reader = BufReader::with_capacity(1024 * 1024, input_file);

    let output_file =
        File::create(&encrypted_path).context("Failed to create encrypted archive file")?;
    let output_writer = BufWriter::with_capacity(1024 * 1024, output_file);

    crate::encryption::encrypt_stream(input_reader, output_writer, recipient)
        .context("Failed to encrypt archive")?;

    let output_size = fs::metadata(&encrypted_path)?.len();
    let elapsed = start_time.elapsed();

    log::info!(
        "Encrypted archive: {} → {} in {:.1}s",
        format_bytes(input_size),
        format_bytes(output_size),
        elapsed.as_secs_f64()
    );

    Ok(encrypted_path)
}

pub fn decrypt_archive(
    encrypted_path: &Path,
    identity: Option<&age::x25519::Identity>,
    passphrase: Option<&age::secrecy::SecretString>,
) -> Result<tempfile::TempPath> {
    let start_time = Instant::now();
    let input_size = fs::metadata(encrypted_path)?.len();

    let temp_file =
        NamedTempFile::new().context("Failed to create temporary file for decrypted archive")?;
    let decrypted_path = temp_file.into_temp_path();

    let input_file = File::open(encrypted_path).context("Failed to open encrypted archive")?;
    let input_reader = BufReader::with_capacity(1024 * 1024, input_file);

    let output_file =
        File::create(&decrypted_path).context("Failed to create decrypted archive file")?;
    let output_writer = BufWriter::with_capacity(1024 * 1024, output_file);

    crate::encryption::decrypt_stream(input_reader, output_writer, identity, passphrase)
        .context("Failed to decrypt archive")?;

    let output_size = fs::metadata(&decrypted_path)?.len();
    let elapsed = start_time.elapsed();

    log::info!(
        "Decrypted archive: {} → {} in {:.1}s",
        format_bytes(input_size),
        format_bytes(output_size),
        elapsed.as_secs_f64()
    );

    Ok(decrypted_path)
}

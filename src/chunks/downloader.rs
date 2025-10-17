use anyhow::{Context, Result};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::{create_dir_all, File};
use tokio::io::AsyncWriteExt;

use crate::api::models::cache::RestoreChunk;
use crate::chunks::store::{AnyStore, ChunkStore};
use crate::manifest::diff::compute_root_digest_from_entries;
use crate::progress::{Reporter, TransferProgress};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

#[cfg(not(unix))]
use crate::ui;

const MAX_RETRIES: u32 = 3;

pub struct ChunkDownloader {
    client: reqwest::Client,
    reporter: Reporter,
    session_id: String,
}

impl ChunkDownloader {
    pub fn new(client: reqwest::Client, reporter: Reporter, session_id: String) -> Self {
        Self {
            client,
            reporter,
            session_id,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn download_chunks(
        &self,
        manifest: &crate::manifest::Manifest,
        store: &AnyStore,
        chunks: &[RestoreChunk],
        step_number: u8,
        progress: Option<TransferProgress>,
        verbose: bool,
    ) -> Result<()> {
        let chunk_lookup: HashMap<String, RestoreChunk> = chunks
            .iter()
            .cloned()
            .map(|chunk| (chunk.digest.clone(), chunk))
            .collect();

        let chunk_metadata_map: HashMap<String, &crate::manifest::ChunkMeta> = manifest
            .chunks
            .iter()
            .map(|meta| (meta.digest.clone(), meta))
            .collect();

        let unique_chunks: HashMap<String, u64> = manifest
            .files
            .iter()
            .filter_map(|f| f.spans.as_ref())
            .flatten()
            .fold(HashMap::new(), |mut acc, span| {
                acc.entry(span.digest.clone()).or_insert(span.length);
                acc
            });

        let total_chunks = unique_chunks.len();

        self.download_chunks_parallel(
            store,
            unique_chunks,
            &chunk_lookup,
            chunk_metadata_map,
            total_chunks,
            step_number,
            progress.clone(),
            verbose,
        )
        .await?;

        if let Some(progress) = progress {
            progress.complete()?;
        }

        Ok(())
    }

    pub async fn reassemble_and_verify(
        &self,
        manifest: &crate::manifest::Manifest,
        store: &AnyStore,
        target_path: &Path,
        expected_content_hash: Option<&str>,
        verbose: bool,
    ) -> Result<()> {
        create_dir_all(target_path).await.with_context(|| {
            format!(
                "Failed to create target directory: {}",
                target_path.display()
            )
        })?;

        self.reassemble_files(manifest, store, target_path, verbose)
            .await?;

        let computed_digest = verify_metadata(manifest, target_path).await?;
        let manifest_digest = &manifest.root.digest;

        if !computed_digest.eq_ignore_ascii_case(manifest_digest) {
            anyhow::bail!(
                "Manifest digest mismatch: manifest {}, computed {}",
                manifest_digest,
                computed_digest
            );
        }

        if let Some(expected_hash) = expected_content_hash {
            if !computed_digest.eq_ignore_ascii_case(expected_hash) {
                anyhow::bail!(
                    "Content hash verification failed: expected {}, computed {}",
                    expected_hash,
                    computed_digest
                );
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn download_chunks_parallel(
        &self,
        store: &AnyStore,
        unique_chunks: HashMap<String, u64>,
        chunk_lookup: &HashMap<String, RestoreChunk>,
        chunk_metadata_map: HashMap<String, &crate::manifest::ChunkMeta>,
        total_chunks: usize,
        step_number: u8,
        progress: Option<TransferProgress>,
        verbose: bool,
    ) -> Result<()> {
        let concurrency = crate::chunks::store::get_download_concurrency();
        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut futs = FuturesUnordered::new();

        for (index, (digest, _size)) in unique_chunks.iter().enumerate() {
            let permit = sem.clone().acquire_owned().await?;
            let client = self.client.clone();
            let chunk_info = chunk_lookup
                .get(digest)
                .ok_or_else(|| anyhow::anyhow!("Missing URL for chunk: {}", digest))?
                .clone();
            let url = chunk_info.url.clone();
            let meta = chunk_metadata_map
                .get(digest)
                .ok_or_else(|| anyhow::anyhow!("Missing metadata for chunk: {}", digest))?;
            let chunk_meta = (*meta).clone();
            let digest = digest.clone();
            let store = match store {
                AnyStore::Mem(s) => AnyStore::Mem(s.clone()),
                AnyStore::Disk(s) => AnyStore::Disk(s.clone()),
            };
            let reporter = self.reporter.clone();
            let session_id = self.session_id.clone();
            let progress = progress.clone();
            let total_chunks = total_chunks as u32;

            futs.push(tokio::spawn(async move {
                let _permit = permit;

                let short_digest = &digest[..12.min(digest.len())];

                if verbose {
                    let _ = reporter.substep_start(
                        session_id.clone(),
                        step_number,
                        (index + 1) as u32,
                        total_chunks,
                        format!("Chunk {}/{}", index + 1, total_chunks),
                        Some(format!("digest {}", short_digest)),
                    );
                }

                let t0 = Instant::now();

                let compressed_data = download_chunk_with_retries(
                    &client,
                    &url,
                    chunk_meta.compressed_size,
                    MAX_RETRIES,
                )
                .await?;

                let uncompressed_data = decompress_chunk(&compressed_data, &chunk_meta)?;

                let mut hasher = Sha256::new();
                hasher.update(&uncompressed_data);
                let actual_hash = hasher.finalize();
                let actual_hex = actual_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                if actual_hex != digest {
                    anyhow::bail!(
                        "Chunk hash mismatch: expected {}, got {}, compressed_size={}, uncompressed_size={}",
                        digest,
                        actual_hex,
                        chunk_meta.compressed_size,
                        chunk_meta.uncompressed_size
                    );
                }

                store.put(&digest, uncompressed_data).await?;

                if let Some(prog) = progress {
                    prog.record_bytes(compressed_data.len() as u64)?;
                }

                if verbose {
                    let elapsed = t0.elapsed();
                    let mbps = (compressed_data.len() as f64 / 1_000_000.0)
                        / elapsed.as_secs_f64().max(0.001);
                    let _ = reporter.substep_complete(
                        session_id,
                        step_number,
                        (index + 1) as u32,
                        total_chunks,
                        elapsed,
                        Some(format!("@ {:.0} MB/s", mbps)),
                    );
                }

                Ok::<(), anyhow::Error>(())
            }));
        }

        while let Some(result) = futs.next().await {
            result??;
        }

        Ok(())
    }

    async fn reassemble_files(
        &self,
        manifest: &crate::manifest::Manifest,
        store: &AnyStore,
        target_dir: &Path,
        _verbose: bool,
    ) -> Result<()> {
        // Create directories first
        for entry in manifest.files.iter().filter(|e| {
            e.state == crate::manifest::EntryState::Present
                && matches!(e.entry_type, crate::manifest::EntryType::Dir)
        }) {
            let dir_path = target_dir.join(&entry.path);
            create_dir_all(&dir_path)
                .await
                .with_context(|| format!("Failed to create directory: {}", entry.path))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(entry.mode))?;
            }
        }

        let write_limit = crate::chunks::store::get_write_concurrency();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(write_limit));
        let target_root = target_dir.to_path_buf();

        let mut tasks = FuturesUnordered::new();

        for entry in manifest.files.iter().filter(|e| {
            e.state == crate::manifest::EntryState::Present
                && matches!(e.entry_type, crate::manifest::EntryType::File)
        }) {
            let entry_clone = entry.clone();
            let store_clone = store.clone();
            let root_clone = target_root.clone();
            let sem = semaphore.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await?;
                write_file(entry_clone, store_clone, root_clone).await
            }));
        }

        while let Some(res) = tasks.next().await {
            res??;
        }

        // Handle symlinks
        for entry in manifest.files.iter().filter(|e| {
            e.state == crate::manifest::EntryState::Present
                && matches!(e.entry_type, crate::manifest::EntryType::Symlink)
        }) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                if let Some(target) = &entry.target {
                    let link_path = target_dir.join(&entry.path);
                    if let Some(parent) = link_path.parent() {
                        create_dir_all(parent).await?;
                    }

                    match symlink(target, &link_path) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                            tokio::fs::remove_file(&link_path).await.with_context(|| {
                                format!("Failed to replace existing symlink: {}", entry.path)
                            })?;

                            symlink(target, &link_path).with_context(|| {
                                format!("Failed to recreate symlink: {}", entry.path)
                            })?;
                        }
                        Err(err) => {
                            return Err(err).with_context(|| {
                                format!("Failed to create symlink: {}", entry.path)
                            });
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            {
                if let Some(target) = &entry.target {
                    ui::warn(&format!(
                        "Symlinks not supported on this platform, skipping {} -> {}",
                        entry.path, target
                    ));
                }
            }
        }

        Ok(())
    }
}

async fn write_file(
    entry: crate::manifest::ManifestFile,
    store: AnyStore,
    target_root: PathBuf,
) -> Result<()> {
    let file_path = target_root.join(&entry.path);

    if let Some(parent) = file_path.parent() {
        create_dir_all(parent).await?;
    }

    let mut out = File::create(&file_path)
        .await
        .with_context(|| format!("Failed to create file: {}", file_path.display()))?;

    let mut written: u64 = 0;

    match (&entry.spans, &entry.hash) {
        (Some(spans), _) if spans.is_empty() => {
            if entry.size > 0 {
                let digest = entry.hash.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("File {} has empty chunk spans with no hash", entry.path)
                })?;

                let chunk_size = store.size_of(digest).ok_or_else(|| {
                    anyhow::anyhow!("Chunk {} not found for {}", digest, entry.path)
                })?;

                if chunk_size != entry.size {
                    anyhow::bail!(
                        "Chunk size mismatch for {} (digest {}, expected {} bytes, got {} bytes)",
                        entry.path,
                        digest,
                        entry.size,
                        chunk_size
                    );
                }

                let chunk = store
                    .read_range(digest, 0, chunk_size)
                    .await
                    .with_context(|| {
                        format!("Failed to read chunk {} for {}", digest, entry.path)
                    })?;

                written = written.saturating_add(chunk.len() as u64);
                out.write_all(&chunk).await.with_context(|| {
                    format!("Failed to write chunk {} for {}", digest, entry.path)
                })?;
            }
        }
        (Some(spans), _) => {
            for span in spans {
                let chunk = store
                    .read_range(&span.digest, span.offset, span.length)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to read chunk span {} for file {}",
                            span.digest, entry.path
                        )
                    })?;

                if chunk.len() != span.length as usize {
                    anyhow::bail!(
                        "Chunk span length mismatch for {} (digest {}, expected {} bytes, got {})",
                        entry.path,
                        span.digest,
                        span.length,
                        chunk.len()
                    );
                }

                written = written.saturating_add(chunk.len() as u64);
                out.write_all(&chunk).await.with_context(|| {
                    format!("Failed to write chunk span for file {}", entry.path)
                })?;
            }
        }
        (None, Some(digest)) if entry.size > 0 => {
            let chunk_size = store
                .size_of(digest)
                .ok_or_else(|| anyhow::anyhow!("Chunk {} not found for {}", digest, entry.path))?;

            if chunk_size != entry.size {
                anyhow::bail!(
                    "Chunk size mismatch for {} (digest {}, expected {} bytes, got {} bytes)",
                    entry.path,
                    digest,
                    entry.size,
                    chunk_size
                );
            }

            let chunk = store
                .read_range(digest, 0, chunk_size)
                .await
                .with_context(|| format!("Failed to read chunk {} for {}", digest, entry.path))?;

            written = written.saturating_add(chunk.len() as u64);
            out.write_all(&chunk)
                .await
                .with_context(|| format!("Failed to write chunk {} for {}", digest, entry.path))?;
        }
        (None, _) => {
            if entry.size > 0 {
                anyhow::bail!("File {} missing chunk spans in manifest", entry.path);
            }
        }
    }

    if written != entry.size {
        anyhow::bail!(
            "Wrote {} bytes for {} but expected {} bytes",
            written,
            entry.path,
            entry.size
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(entry.mode))?;
    }

    Ok(())
}

async fn download_chunk_with_retries(
    client: &reqwest::Client,
    url: &str,
    expected_size: u64,
    max_retries: u32,
) -> Result<Vec<u8>> {
    let mut attempts = 0;
    let mut last_error = None;

    while attempts < max_retries {
        match download_chunk_simple(client, url, expected_size).await {
            Ok(data) => return Ok(data),
            Err(e) => {
                attempts += 1;
                last_error = Some(e);
                if attempts < max_retries {
                    let delay = std::time::Duration::from_millis(100 * 2_u64.pow(attempts));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    Err(last_error.unwrap())
}

async fn download_chunk_simple(
    client: &reqwest::Client,
    url: &str,
    expected_size: u64,
) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to send download request")?;

    if !response.status().is_success() {
        anyhow::bail!("Download failed with status: {}", response.status());
    }

    let mut buf = Vec::with_capacity(expected_size as usize);
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read chunk from stream")?;
        buf.extend_from_slice(&chunk);
    }

    if buf.len() != expected_size as usize {
        anyhow::bail!(
            "Size mismatch: expected {} bytes, got {}",
            expected_size,
            buf.len()
        );
    }

    Ok(buf)
}

fn decompress_chunk(compressed_data: &[u8], meta: &crate::manifest::ChunkMeta) -> Result<Vec<u8>> {
    let mut decompressed = Vec::with_capacity(meta.uncompressed_size as usize);
    zstd::stream::copy_decode(compressed_data, &mut decompressed)
        .context("Failed to decompress chunk")?;
    Ok(decompressed)
}

async fn verify_metadata(
    manifest: &crate::manifest::Manifest,
    target_dir: &Path,
) -> Result<String> {
    use crate::manifest::{EntryState, EntryType};
    use tokio::fs::{metadata, read_link};

    let mut entries = manifest.files.clone();
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let mut lookup: HashMap<String, crate::manifest::ManifestFile> = HashMap::new();
    for entry in entries.iter().filter(|e| e.state == EntryState::Present) {
        lookup.insert(entry.path.clone(), entry.clone());
    }

    let mut seen = HashSet::new();

    for entry in WalkDir::new(target_dir)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
    {
        let entry = entry?;
        let file_type = entry.file_type();

        let entry_type = if file_type.is_file() {
            EntryType::File
        } else if file_type.is_dir() {
            EntryType::Dir
        } else if file_type.is_symlink() {
            EntryType::Symlink
        } else {
            continue;
        };

        let relative = entry
            .path()
            .strip_prefix(target_dir)
            .unwrap()
            .to_string_lossy()
            .replace("\\", "/");

        let manifest_entry = lookup.get(&relative).ok_or_else(|| {
            anyhow::anyhow!(
                "Unexpected item restored that was not in manifest: {}",
                relative
            )
        })?;

        match entry_type {
            EntryType::File => {
                let meta = metadata(entry.path())
                    .await
                    .with_context(|| format!("Failed to stat restored file: {}", relative))?;
                if !meta.is_file() {
                    anyhow::bail!("Expected file but found something else: {}", relative);
                }
                if meta.len() != manifest_entry.size {
                    anyhow::bail!(
                        "Size mismatch for {} (expected {} bytes, found {})",
                        relative,
                        manifest_entry.size,
                        meta.len()
                    );
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.mode() != manifest_entry.mode {
                        anyhow::bail!(
                            "Mode mismatch for {} (expected {:o}, found {:o})",
                            relative,
                            manifest_entry.mode,
                            meta.mode()
                        );
                    }
                }
            }
            EntryType::Dir => {
                let meta = metadata(entry.path())
                    .await
                    .with_context(|| format!("Failed to stat restored directory: {}", relative))?;
                if !meta.is_dir() {
                    anyhow::bail!("Expected directory but found something else: {}", relative);
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.mode() != manifest_entry.mode {
                        anyhow::bail!(
                            "Mode mismatch for {} (expected {:o}, found {:o})",
                            relative,
                            manifest_entry.mode,
                            meta.mode()
                        );
                    }
                }
            }
            EntryType::Symlink => {
                let actual = read_link(entry.path())
                    .await
                    .with_context(|| format!("Failed to read symlink target for {}", relative))?;
                let expected_target = manifest_entry.target.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("Symlink entry missing target in manifest for {}", relative)
                })?;

                if actual != Path::new(expected_target) {
                    anyhow::bail!(
                        "Symlink target mismatch for {} (expected {}, found {})",
                        relative,
                        expected_target,
                        actual.display()
                    );
                }
            }
        }

        seen.insert(relative);
    }

    for (path, entry) in lookup.iter() {
        if !seen.contains(path) && entry.entry_type != EntryType::Dir {
            anyhow::bail!("Expected item missing after restore: {}", path);
        }
    }

    Ok(compute_root_digest_from_entries(&entries))
}

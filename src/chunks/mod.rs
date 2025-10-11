pub mod cdc;
pub mod downloader;
pub mod store;
pub mod uploader;

use anyhow::{Context, Result};
use rayon::{prelude::*, ThreadPool, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, BufReader};
use zstd::stream::raw::CParameter;

use crate::manifest::{
    ChunkSpan as ManifestChunkSpan, EntryState, EntryType, ManifestDraft, ManifestFile,
};
use crate::platform::resources::{MemoryStrategy, SystemResources};
use crate::ui;

pub use downloader::ChunkDownloader;
pub use uploader::ChunkUploader;

const MIN_CHUNK_SIZE: usize = 32 * 1024 * 1024; // 32 MiB
const MAX_CHUNK_SIZE: usize = 128 * 1024 * 1024; // 128 MiB
const READ_BUFFER_SIZE: usize = 512 * 1024; // 512 KiB
const MAX_ALLOWED_CHUNK_SIZE: usize = 128 * 1024 * 1024; // 128 MiB ceiling for CDC
const CHUNK_COMPRESSION: &str = "zstd";

struct FileRecord {
    start: u64,
    length: u64,
    expected_size: u64,
}

struct ReadyChunk {
    hash: String,
    key: String,
    data: Vec<u8>,
    uncompressed_size: u64,
    start_offset: u64,
}

pub struct StreamingChunker {
    chunks_dir: PathBuf,
    chunk_params: ChunkingParams,
    cdc: cdc::CdcState,
    buffer: Vec<u8>,
    ready_chunks: Vec<ReadyChunk>,
    chunk_refs: Vec<ChunkRef>,
    unique_chunks: HashMap<String, UniqueChunk>,
    file_start_offset: u64,
    total_bytes_written: u64,
    base_dir_ensured: bool,
    compression_level: i32,
    parallelism: usize,
    max_buffered_chunks: usize,
    thread_pool: Option<Arc<ThreadPool>>,
    chunk_cache_root: PathBuf,
    file_records: Vec<FileRecord>,
}

#[derive(Clone)]
struct UniqueChunk {
    path: PathBuf,
    key: String,
    compressed_size: u64,
    compressed_hash: String,
}

struct MaterializedChunk {
    hash: String,
    key: String,
    path: PathBuf,
    compressed_size: u64,
    compressed_hash: String,
}

struct ChunkOccurrence {
    hash: String,
    start_offset: u64,
    uncompressed_size: u64,
}

#[derive(Debug, Clone)]
pub struct ChunkSpan {
    pub digest: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub struct ChunkRef {
    pub path: PathBuf,
    pub hash: String,
    pub key: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub compressed_hash: String,
    pub start_offset: u64,
}

impl StreamingChunker {
    pub fn new(
        chunks_dir: PathBuf,
        chunk_params: ChunkingParams,
        compression_level: i32,
        parallelism: usize,
    ) -> Self {
        let adjusted_params = chunk_params.clamp(MAX_ALLOWED_CHUNK_SIZE);
        let avg_capacity = adjusted_params.avg_size;
        let parallelism = parallelism.max(1);
        let max_buffered_chunks = (parallelism * 2).max(1);
        let thread_pool = if parallelism > 1 {
            match ThreadPoolBuilder::new()
                .num_threads(parallelism)
                .thread_name(|idx| format!("boringcache-chunker-{idx}"))
                .build()
            {
                Ok(pool) => Some(Arc::new(pool)),
                Err(err) => {
                    log::warn!(
                        "Failed to build chunking thread pool (falling back to single-threaded): {err}"
                    );
                    None
                }
            }
        } else {
            None
        };
        let chunk_cache_root = resolve_chunk_cache_root().unwrap_or_else(|err| {
            log::warn!(
                "Failed to initialize chunk cache root (falling back to staging dir): {err}"
            );
            chunks_dir.clone()
        });
        Self {
            chunks_dir,
            chunk_params: adjusted_params,
            cdc: cdc::CdcState::new(adjusted_params),
            buffer: Vec::with_capacity(avg_capacity),
            ready_chunks: Vec::new(),
            chunk_refs: Vec::new(),
            unique_chunks: HashMap::new(),
            file_start_offset: 0,
            total_bytes_written: 0,
            base_dir_ensured: false,
            compression_level,
            parallelism,
            max_buffered_chunks,
            thread_pool,
            chunk_cache_root,
            file_records: Vec::new(),
        }
    }

    pub async fn feed_file(&mut self, file_path: &Path, expected_size: u64) -> Result<usize> {
        self.file_start_offset = self.total_bytes_written;

        let file = TokioFile::open(file_path)
            .await
            .with_context(|| format!("Failed to open file: {}", file_path.display()))?;

        let mut reader = BufReader::with_capacity(READ_BUFFER_SIZE, file);
        let mut read_buffer = vec![0u8; READ_BUFFER_SIZE];

        loop {
            let n = reader
                .read(&mut read_buffer)
                .await
                .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

            if n == 0 {
                break;
            }

            self.feed_bytes(&read_buffer[..n]);
            if self.ready_chunks.len() >= self.max_buffered_chunks {
                self.flush_ready_chunks().await?;
            }
        }

        self.flush_ready_chunks().await?;

        let file_length = self.total_bytes_written - self.file_start_offset;

        if file_length != expected_size {
            anyhow::bail!(
                "File size changed during chunking: {} (expected {}, got {})",
                file_path.display(),
                expected_size,
                file_length
            );
        }

        self.file_records.push(FileRecord {
            start: self.file_start_offset,
            length: file_length,
            expected_size,
        });

        Ok(self.file_records.len() - 1)
    }

    fn feed_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.buffer.push(byte);
            self.total_bytes_written += 1;

            let should_cut = self.cdc.update(byte);
            if self.cdc.should_force() || should_cut {
                self.finalize_chunk();
            }
        }
    }

    fn finalize_chunk(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        let uncompressed_data = std::mem::take(&mut self.buffer);
        self.buffer = Vec::with_capacity(self.chunk_params.avg_size);
        let uncompressed_size = uncompressed_data.len() as u64;
        let hash = compute_chunk_hash(&uncompressed_data);
        let key = generate_chunk_key(&hash);

        let chunk_start_offset = self.total_bytes_written - uncompressed_size;

        self.ready_chunks.push(ReadyChunk {
            hash,
            key,
            data: uncompressed_data,
            uncompressed_size,
            start_offset: chunk_start_offset,
        });
        self.cdc.reset();
    }

    async fn ensure_base_dir(&mut self) -> Result<()> {
        if self.base_dir_ensured {
            return Ok(());
        }

        tokio::fs::create_dir_all(&self.chunks_dir)
            .await
            .with_context(|| {
                format!(
                    "Failed to create chunks directory: {}",
                    self.chunks_dir.display()
                )
            })?;
        self.base_dir_ensured = true;
        Ok(())
    }

    async fn flush_ready_chunks(&mut self) -> Result<()> {
        if self.ready_chunks.is_empty() {
            return Ok(());
        }

        self.ensure_base_dir().await?;

        let pending = std::mem::take(&mut self.ready_chunks);
        let mut occurrences = Vec::with_capacity(pending.len());
        let mut new_jobs = Vec::new();
        let mut scheduled = HashMap::new();

        for chunk in pending {
            let hash = chunk.hash.clone();
            let start_offset = chunk.start_offset;
            let uncompressed_size = chunk.uncompressed_size;

            if self.unique_chunks.contains_key(hash.as_str()) {
                occurrences.push(ChunkOccurrence {
                    hash,
                    start_offset,
                    uncompressed_size,
                });
                continue;
            }

            match scheduled.entry(hash.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(new_jobs.len());
                    occurrences.push(ChunkOccurrence {
                        hash,
                        start_offset,
                        uncompressed_size,
                    });
                    new_jobs.push(chunk);
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    occurrences.push(ChunkOccurrence {
                        hash,
                        start_offset,
                        uncompressed_size,
                    });
                    // drop chunk data; already scheduled
                }
            }
        }

        let materialized = self.materialize_new_chunks(new_jobs)?;

        for mat in materialized {
            let unique = UniqueChunk {
                path: mat.path.clone(),
                key: mat.key.clone(),
                compressed_size: mat.compressed_size,
                compressed_hash: mat.compressed_hash.clone(),
            };
            self.unique_chunks.entry(mat.hash.clone()).or_insert(unique);
        }

        for occurrence in occurrences {
            let hash = occurrence.hash;
            let start_offset = occurrence.start_offset;
            let uncompressed_size = occurrence.uncompressed_size;

            let unique = self
                .unique_chunks
                .get(hash.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing metadata for chunk {}", hash))?;

            self.chunk_refs.push(ChunkRef {
                path: unique.path.clone(),
                hash,
                key: unique.key.clone(),
                uncompressed_size,
                compressed_size: unique.compressed_size,
                compressed_hash: unique.compressed_hash.clone(),
                start_offset,
            });
        }

        Ok(())
    }

    fn materialize_new_chunks(&self, jobs: Vec<ReadyChunk>) -> Result<Vec<MaterializedChunk>> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let mut results: Vec<Option<MaterializedChunk>> =
            std::iter::repeat_with(|| None).take(jobs.len()).collect();
        let mut pending_indices = Vec::new();
        let mut to_compress = Vec::new();

        for (idx, chunk) in jobs.into_iter().enumerate() {
            match load_cached_chunk(
                &self.chunk_cache_root,
                chunk.key.as_str(),
                chunk.hash.as_str(),
                chunk.uncompressed_size,
            ) {
                Ok(Some(cached)) => {
                    results[idx] = Some(MaterializedChunk {
                        hash: chunk.hash,
                        key: chunk.key,
                        path: cached.path,
                        compressed_size: cached.compressed_size,
                        compressed_hash: cached.compressed_hash,
                    });
                }
                Ok(None) => {
                    pending_indices.push(idx);
                    to_compress.push(chunk);
                }
                Err(err) => {
                    log::warn!(
                        "Failed to read cached chunk metadata (falling back to recompress): {err}"
                    );
                    pending_indices.push(idx);
                    to_compress.push(chunk);
                }
            }
        }

        if !to_compress.is_empty() {
            let compressed = compress_chunks_parallel(
                to_compress,
                self.compression_level,
                self.parallelism,
                self.thread_pool.as_deref(),
                &self.chunk_cache_root,
            )?;

            for (idx, chunk) in pending_indices.into_iter().zip(compressed.into_iter()) {
                results[idx] = Some(chunk);
            }
        }

        let mut finalized = Vec::with_capacity(results.len());
        for entry in results {
            if let Some(chunk) = entry {
                finalized.push(chunk);
            } else {
                anyhow::bail!("Failed to materialize chunk metadata");
            }
        }

        Ok(finalized)
    }

    pub async fn finalize_to_file(mut self) -> Result<(Vec<ChunkRef>, Vec<Vec<ChunkSpan>>)> {
        if !self.buffer.is_empty() {
            self.finalize_chunk();
        }

        self.flush_ready_chunks().await?;
        let spans = self.build_file_spans()?;
        Ok((self.chunk_refs, spans))
    }

    fn build_file_spans(&self) -> Result<Vec<Vec<ChunkSpan>>> {
        let mut result = Vec::with_capacity(self.file_records.len());
        let mut chunk_index = 0;

        for record in &self.file_records {
            let mut remaining = record.length;
            let mut cursor = record.start;
            let mut spans = Vec::new();

            while remaining > 0 {
                let chunk = loop {
                    let chunk = self
                        .chunk_refs
                        .get(chunk_index)
                        .ok_or_else(|| anyhow::anyhow!("Chunk missing while building spans"))?;

                    let chunk_start = chunk.start_offset;
                    let chunk_end = chunk_start + chunk.uncompressed_size;

                    if cursor >= chunk_end {
                        chunk_index += 1;
                        continue;
                    }

                    if cursor < chunk_start {
                        anyhow::bail!(
                            "File offset {} precedes chunk start {} while building spans",
                            cursor,
                            chunk_start
                        );
                    }

                    break chunk;
                };

                let chunk_start = chunk.start_offset;
                let offset_in_chunk = cursor - chunk_start;
                let chunk_available = chunk.uncompressed_size - offset_in_chunk;
                let span_len = remaining.min(chunk_available);

                spans.push(ChunkSpan {
                    digest: chunk.hash.clone(),
                    offset: offset_in_chunk,
                    length: span_len,
                });

                cursor += span_len;
                remaining -= span_len;

                if cursor >= chunk_start + chunk.uncompressed_size {
                    chunk_index += 1;
                }
            }

            if record.length != record.expected_size {
                anyhow::bail!(
                    "Recorded file length mismatch (expected {}, got {})",
                    record.expected_size,
                    record.length
                );
            }

            result.push(spans);
        }

        Ok(result)
    }
}

fn compress_chunks_parallel(
    chunks: Vec<ReadyChunk>,
    compression_level: i32,
    parallelism: usize,
    pool: Option<&ThreadPool>,
    cache_root: &Path,
) -> Result<Vec<MaterializedChunk>> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }

    if parallelism > 1 && chunks.len() > 1 {
        if let Some(pool) = pool {
            return pool.install(|| -> Result<Vec<MaterializedChunk>> {
                chunks
                    .into_par_iter()
                    .with_max_len(8)
                    .map(|chunk| -> Result<MaterializedChunk> {
                        let mut compressor = create_compressor(compression_level, parallelism)?;
                        compress_and_store_chunk(&mut compressor, chunk, parallelism, cache_root)
                    })
                    .collect::<Result<Vec<_>>>()
            });
        }
    }

    let mut compressor = create_compressor(compression_level, parallelism)?;
    chunks
        .into_iter()
        .map(|chunk| compress_and_store_chunk(&mut compressor, chunk, parallelism, cache_root))
        .collect::<Result<Vec<_>>>()
}

fn create_compressor(
    compression_level: i32,
    parallelism: usize,
) -> Result<zstd::bulk::Compressor<'static>> {
    let mut compressor = zstd::bulk::Compressor::new(compression_level)
        .context("Failed to create zstd compressor")?;
    if parallelism > 1 {
        let _ = compressor.set_parameter(CParameter::NbWorkers(0));
    }
    Ok(compressor)
}

fn compress_and_store_chunk(
    compressor: &mut zstd::bulk::Compressor<'static>,
    chunk: ReadyChunk,
    parallelism: usize,
    cache_root: &Path,
) -> Result<MaterializedChunk> {
    let data_len = chunk.data.len();
    if parallelism > 1 {
        let _ = compressor.set_parameter(CParameter::NbWorkers(0));
    } else if let Some(workers) = recommended_compression_workers(data_len) {
        let _ = compressor.set_parameter(CParameter::NbWorkers(workers as u32));
    } else {
        let _ = compressor.set_parameter(CParameter::NbWorkers(0));
    }

    let ReadyChunk {
        hash,
        key,
        data,
        uncompressed_size,
        start_offset: _,
    } = chunk;

    let compressed_data = compressor
        .compress(&data)
        .context("zstd compression should not fail")?;
    let compressed_hash = format!("blake3:{}", blake3::hash(&compressed_data).to_hex());
    let compressed_size = compressed_data.len() as u64;

    let (data_path, meta_path) = chunk_cache_paths(cache_root, &key)?;
    if let Some(parent) = data_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create chunk cache directory: {}",
                parent.display()
            )
        })?;
    }

    let temp_path = data_path.with_extension("tmp");
    {
        let mut file = File::create(&temp_path).with_context(|| {
            format!("Failed to create temp chunk file: {}", temp_path.display())
        })?;
        file.write_all(&compressed_data)
            .with_context(|| format!("Failed to write chunk data: {}", temp_path.display()))?;
        let _ = file.sync_all();
    }

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
            digest: hash.clone(),
            compression: Cow::Borrowed(CHUNK_COMPRESSION),
            uncompressed_size,
            compressed_size,
            compressed_hash: compressed_hash.clone(),
        },
    )?;

    Ok(MaterializedChunk {
        hash,
        key,
        path: data_path,
        compressed_size,
        compressed_hash,
    })
}

fn load_cached_chunk(
    cache_root: &Path,
    key: &str,
    hash: &str,
    expected_uncompressed: u64,
) -> Result<Option<CachedChunkRecord>> {
    let (data_path, meta_path) = chunk_cache_paths(cache_root, key)?;
    if !(data_path.exists() && meta_path.exists()) {
        return Ok(None);
    }

    let mut buffer = Vec::new();
    File::open(&meta_path)
        .with_context(|| format!("Failed to open chunk metadata: {}", meta_path.display()))?
        .read_to_end(&mut buffer)
        .with_context(|| {
            format!(
                "Failed to read chunk metadata file: {}",
                meta_path.display()
            )
        })?;

    let metadata: CachedChunkMetadata = match serde_json::from_slice(&buffer) {
        Ok(meta) => meta,
        Err(err) => {
            log::warn!(
                "Failed to parse cached chunk metadata ({}): {}",
                meta_path.display(),
                err
            );
            invalidate_cached_chunk(&data_path, &meta_path);
            return Ok(None);
        }
    };

    if metadata.digest != hash {
        log::debug!(
            "Cached chunk digest mismatch (expected {}, found {})",
            hash,
            metadata.digest
        );
        invalidate_cached_chunk(&data_path, &meta_path);
        return Ok(None);
    }

    if metadata.uncompressed_size != expected_uncompressed {
        log::debug!(
            "Cached chunk size mismatch (expected {} bytes, found {} bytes)",
            expected_uncompressed,
            metadata.uncompressed_size
        );
        invalidate_cached_chunk(&data_path, &meta_path);
        return Ok(None);
    }

    if metadata.compression.as_ref() != CHUNK_COMPRESSION {
        log::warn!(
            "Unsupported compression algorithm in cache metadata: {} (expected {})",
            metadata.compression,
            CHUNK_COMPRESSION
        );
        invalidate_cached_chunk(&data_path, &meta_path);
        return Ok(None);
    }

    let actual_size = fs::metadata(&data_path)
        .with_context(|| format!("Failed to stat cached chunk: {}", data_path.display()))?
        .len();
    if actual_size != metadata.compressed_size {
        log::debug!(
            "Cached chunk compressed size mismatch (expected {} bytes, found {} bytes)",
            metadata.compressed_size,
            actual_size
        );
        invalidate_cached_chunk(&data_path, &meta_path);
        return Ok(None);
    }

    Ok(Some(CachedChunkRecord {
        path: data_path,
        compressed_size: metadata.compressed_size,
        compressed_hash: metadata.compressed_hash,
    }))
}

fn chunk_cache_paths(cache_root: &Path, key: &str) -> Result<(PathBuf, PathBuf)> {
    let relative = Path::new(key);
    let data_path = cache_root.join(relative);
    let meta_path = data_path.with_extension("meta");
    Ok((data_path, meta_path))
}

fn write_cached_chunk_metadata(path: &Path, metadata: &CachedChunkMetadata) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create metadata directory: {}", parent.display())
        })?;
    }

    let temp_path = path.with_extension("tmp");
    {
        let data = serde_json::to_vec(metadata).context("Failed to serialize chunk metadata")?;
        let mut file = File::create(&temp_path).with_context(|| {
            format!(
                "Failed to create temp metadata file: {}",
                temp_path.display()
            )
        })?;
        file.write_all(&data)
            .with_context(|| format!("Failed to write chunk metadata: {}", temp_path.display()))?;
        let _ = file.sync_all();
    }

    if let Err(err) = fs::rename(&temp_path, path) {
        if path.exists() {
            let _ = fs::remove_file(path);
            fs::rename(&temp_path, path)
                .with_context(|| format!("Failed to finalize metadata file: {}", path.display()))?;
        } else {
            return Err(err)
                .with_context(|| format!("Failed to finalize metadata file: {}", path.display()));
        }
    }

    Ok(())
}

fn invalidate_cached_chunk(data_path: &Path, meta_path: &Path) {
    if let Err(err) = fs::remove_file(data_path) {
        if err.kind() != ErrorKind::NotFound {
            log::debug!(
                "Failed to remove cached chunk file {}: {}",
                data_path.display(),
                err
            );
        }
    }
    if let Err(err) = fs::remove_file(meta_path) {
        if err.kind() != ErrorKind::NotFound {
            log::debug!(
                "Failed to remove cached chunk metadata {}: {}",
                meta_path.display(),
                err
            );
        }
    }
}

fn resolve_chunk_cache_root() -> Result<PathBuf> {
    if let Ok(path) = env::var("BORINGCACHE_CHUNK_CACHE_DIR") {
        let path = PathBuf::from(path);
        fs::create_dir_all(&path).with_context(|| {
            format!(
                "Failed to create BORINGCACHE_CHUNK_CACHE_DIR: {}",
                path.display()
            )
        })?;
        return Ok(path);
    }

    if let Some(mut dir) = dirs::cache_dir() {
        dir.push("boringcache");
        dir.push("chunks");
        fs::create_dir_all(&dir).with_context(|| {
            format!("Failed to create chunk cache directory: {}", dir.display())
        })?;
        return Ok(dir);
    }

    let mut fallback = env::temp_dir();
    fallback.push("boringcache");
    fallback.push("chunks");
    fs::create_dir_all(&fallback).with_context(|| {
        format!(
            "Failed to create fallback chunk cache directory: {}",
            fallback.display()
        )
    })?;
    Ok(fallback)
}

#[derive(Serialize, Deserialize)]
struct CachedChunkMetadata {
    digest: String,
    compression: Cow<'static, str>,
    uncompressed_size: u64,
    compressed_size: u64,
    compressed_hash: String,
}

struct CachedChunkRecord {
    path: PathBuf,
    compressed_size: u64,
    compressed_hash: String,
}

pub async fn chunk_all_files_streaming(
    draft: &ManifestDraft,
    base_path: &str,
    chunks_dir: PathBuf,
    verbose: bool,
) -> Result<(Vec<ChunkRef>, Vec<ManifestFile>)> {
    let resources = SystemResources::detect();
    let chunk_params = determine_chunking_params(draft, resources);
    let compression_level = determine_compression_level(chunk_params.avg_size, resources);
    let parallelism = determine_chunk_parallelism(resources);

    if verbose {
        ui::info(&format!(
            "  Using CDC chunking: target {} MiB (min {} MiB, max {} MiB) @ zstd level {} (parallel {} workers)",
            chunk_params.avg_size / (1024 * 1024),
            chunk_params.min_size / (1024 * 1024),
            chunk_params.max_size / (1024 * 1024),
            compression_level,
            parallelism
        ));
    }

    let mut chunker =
        StreamingChunker::new(chunks_dir, chunk_params, compression_level, parallelism);

    // Check if base_path is a file or directory
    let base_is_file = Path::new(base_path).is_file();

    for desc in &draft.descriptors {
        // If base_path is a single file, use it directly; otherwise join with relative path
        let full_path = if base_is_file && draft.descriptors.len() == 1 {
            PathBuf::from(base_path)
        } else {
            Path::new(base_path).join(&desc.path)
        };

        if desc.entry_type == EntryType::File {
            if verbose {
                ui::info(&format!("  Processing: {}", desc.path));
            }

            chunker.feed_file(&full_path, desc.size).await?;
        }
    }

    let (chunk_refs, file_spans) = chunker.finalize_to_file().await?;

    let mut file_spans_iter = file_spans.into_iter();

    let mut manifest_files = Vec::new();

    for desc in &draft.descriptors {
        match desc.entry_type {
            EntryType::File => {
                let spans = file_spans_iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Missing spans for file {}", desc.path))?;

                let manifest_spans: Vec<ManifestChunkSpan> = spans
                    .iter()
                    .map(|span| ManifestChunkSpan {
                        digest: span.digest.clone(),
                        offset: span.offset,
                        length: span.length,
                    })
                    .collect();

                let whole_file_hash = if manifest_spans.len() == 1 && manifest_spans[0].offset == 0
                {
                    manifest_spans[0].digest.clone()
                } else {
                    format!("blake3:multipart-{}-spans", manifest_spans.len())
                };

                manifest_files.push(ManifestFile {
                    path: desc.path.clone(),
                    entry_type: EntryType::File,
                    size: desc.size,
                    mode: desc.mode,
                    hash: Some(whole_file_hash),
                    spans: Some(manifest_spans),
                    target: None,
                    state: EntryState::Present,
                });
            }
            EntryType::Dir => {
                manifest_files.push(ManifestFile {
                    path: desc.path.clone(),
                    entry_type: EntryType::Dir,
                    size: 0,
                    mode: desc.mode,
                    hash: None,
                    spans: None,
                    target: None,
                    state: EntryState::Present,
                });
            }
            EntryType::Symlink => {
                manifest_files.push(ManifestFile {
                    path: desc.path.clone(),
                    entry_type: EntryType::Symlink,
                    size: 0,
                    mode: desc.mode,
                    hash: None,
                    spans: None,
                    target: desc.target.clone(),
                    state: EntryState::Present,
                });
            }
        }
    }

    if verbose {
        ui::info(&format!("  Total chunks created: {}", chunk_refs.len()));
    }

    Ok((chunk_refs, manifest_files))
}

fn compute_chunk_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    format!("blake3:{}", hash.to_hex())
}

fn generate_chunk_key(hash: &str) -> String {
    let hex = hash.strip_prefix("blake3:").unwrap_or(hash);

    if hex.len() < 4 {
        return format!("chunks/{}", hex);
    }

    let fanout1 = &hex[0..2];
    let fanout2 = &hex[2..4];
    format!("chunks/{}/{}/{}", fanout1, fanout2, hex)
}

fn determine_compression_level(chunk_size: usize, resources: &SystemResources) -> i32 {
    if let Ok(val) = env::var("BORINGCACHE_ZSTD_LEVEL") {
        if let Ok(parsed) = val.parse::<i32>() {
            return parsed.clamp(1, 21);
        }
    }

    // Default to the fastest general-purpose level for first-time uploads.
    // Higher ratios are opt-in via BORINGCACHE_ZSTD_LEVEL.
    let mut level = 1;

    if resources.is_high_performance() && chunk_size > 64 * 1024 * 1024 {
        level = 2;
    }

    level
}

fn recommended_compression_workers(data_len: usize) -> Option<i32> {
    if let Ok(val) = env::var("BORINGCACHE_ZSTD_WORKERS") {
        if let Ok(parsed) = val.parse::<i32>() {
            return Some(parsed.clamp(1, 8));
        }
    }

    let system = SystemResources::detect();

    if system.cpu_cores < 4 {
        return None;
    }

    let mut max_workers = (system.cpu_cores.saturating_sub(2)) as i32;
    if max_workers < 2 {
        return None;
    }

    max_workers = max_workers.min(8);

    if data_len >= 96 * 1024 * 1024 {
        Some(max_workers)
    } else if data_len >= 48 * 1024 * 1024 {
        Some(max_workers.clamp(2, 4))
    } else if data_len >= 24 * 1024 * 1024 {
        Some(2)
    } else {
        None
    }
}

fn determine_target_chunk_size(draft: &ManifestDraft, resources: &SystemResources) -> usize {
    const GIB: u64 = 1024 * 1024 * 1024;
    let dataset_preference = if draft.raw_size <= 16 * GIB {
        64 * 1024 * 1024
    } else {
        MAX_CHUNK_SIZE
    };

    let strategy_cap = match resources.memory_strategy {
        MemoryStrategy::Balanced => MIN_CHUNK_SIZE,
        MemoryStrategy::Aggressive => 64 * 1024 * 1024,
        MemoryStrategy::UltraAggressive => MAX_CHUNK_SIZE,
    };

    let env_cap = env::var("BORINGCACHE_CHUNK_SIZE_MAX")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .and_then(|mb| mb.checked_mul(1024))
        .and_then(|kb| kb.checked_mul(1024))
        .and_then(|bytes| {
            if bytes > usize::MAX as u64 {
                None
            } else {
                Some(bytes as usize)
            }
        })
        .map(allowed_chunk_size)
        .unwrap_or(MAX_CHUNK_SIZE);

    let budget_cap = budget_chunk_ceiling(resources);

    let hard_cap = strategy_cap.min(env_cap).min(budget_cap);

    if dataset_preference <= hard_cap {
        dataset_preference
    } else {
        hard_cap
    }
}

fn determine_chunking_params(draft: &ManifestDraft, resources: &SystemResources) -> ChunkingParams {
    let avg_target = determine_target_chunk_size(draft, resources);
    let avg_size = avg_target
        .next_power_of_two()
        .clamp(MIN_CHUNK_SIZE, MAX_ALLOWED_CHUNK_SIZE);
    let min_size = (avg_size / 2).max(8 * 1024 * 1024);
    let mut max_size = avg_size.saturating_mul(2).min(MAX_ALLOWED_CHUNK_SIZE);
    if max_size < avg_size {
        max_size = avg_size;
    }

    ChunkingParams {
        min_size,
        avg_size,
        max_size,
    }
}

fn determine_chunk_parallelism(resources: &SystemResources) -> usize {
    if let Ok(val) = env::var("BORINGCACHE_CHUNK_THREADS") {
        if let Ok(parsed) = val.parse::<usize>() {
            return parsed.clamp(1, 16);
        }
    }

    let mut threads = resources.max_parallel_chunks.max(1);
    let is_ci = env::var("CI").is_ok();

    threads = if is_ci {
        threads.min(4)
    } else {
        threads.min(8)
    };

    threads.max(1)
}

fn budget_chunk_ceiling(resources: &SystemResources) -> usize {
    let parallel = resources.max_parallel_chunks.max(1) as u64;
    let available_bytes = (resources.available_memory_gb * 1024.0 * 1024.0 * 1024.0) as u64;

    let budget_ratio = match resources.memory_strategy {
        MemoryStrategy::Balanced => 0.20,
        MemoryStrategy::Aggressive => 0.30,
        MemoryStrategy::UltraAggressive => 0.40,
    };

    let mut budget_bytes = (available_bytes as f64 * budget_ratio) as u64;
    if budget_bytes < (MIN_CHUNK_SIZE as u64 * parallel) {
        budget_bytes = MIN_CHUNK_SIZE as u64 * parallel;
    }

    let per_chunk = (budget_bytes / parallel).max(MIN_CHUNK_SIZE as u64);
    allowed_chunk_size(per_chunk as usize)
}

fn allowed_chunk_size(limit: usize) -> usize {
    if limit >= MAX_CHUNK_SIZE {
        MAX_CHUNK_SIZE
    } else if limit >= 64 * 1024 * 1024 {
        64 * 1024 * 1024
    } else {
        MIN_CHUNK_SIZE
    }
}

#[derive(Clone, Copy)]
pub struct ChunkingParams {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
}

impl ChunkingParams {
    fn clamp(self, hard_cap: usize) -> Self {
        let avg_size = self.avg_size.min(hard_cap);
        let max_size = self.max_size.min(hard_cap).max(avg_size);
        let min_size = self.min_size.min(avg_size).max(1);

        Self {
            min_size,
            avg_size,
            max_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn generate_chunk_key_fanout() {
        let hash = "blake3:abcdef1234567890";
        let key = generate_chunk_key(hash);
        assert_eq!(key, "chunks/ab/cd/abcdef1234567890");
    }

    #[test]
    fn compute_chunk_hash_prefix() {
        let data = b"test data";
        let hash = compute_chunk_hash(data);
        assert!(hash.starts_with("blake3:"));
        assert_eq!(hash.len(), 71);
    }

    #[tokio::test]
    async fn streaming_chunker_does_not_create_per_file_chunks() {
        let temp = tempdir().unwrap();
        let chunks_dir = temp.path().join("chunks");

        let file_a = temp.path().join("a.bin");
        let file_b = temp.path().join("b.bin");

        tokio::fs::write(&file_a, vec![0u8; 512 * 1024])
            .await
            .expect("write file a");
        tokio::fs::write(&file_b, vec![1u8; 512 * 1024])
            .await
            .expect("write file b");

        let resources = SystemResources::detect();
        let level = determine_compression_level(MIN_CHUNK_SIZE, resources);
        let params = ChunkingParams {
            min_size: MIN_CHUNK_SIZE / 2,
            avg_size: MIN_CHUNK_SIZE,
            max_size: MIN_CHUNK_SIZE,
        };
        let mut chunker = StreamingChunker::new(chunks_dir, params, level, 1);

        chunker
            .feed_file(&file_a, (512 * 1024) as u64)
            .await
            .expect("chunk first file");
        chunker
            .feed_file(&file_b, (512 * 1024) as u64)
            .await
            .expect("chunk second file");

        let (chunk_refs, file_spans) = chunker.finalize_to_file().await.expect("finalize chunker");

        assert!(!chunk_refs.is_empty() && chunk_refs.len() <= 2);
        assert_eq!(file_spans.len(), 2);
        let span0: u64 = file_spans[0].iter().map(|s| s.length).sum();
        let span1: u64 = file_spans[1].iter().map(|s| s.length).sum();
        assert_eq!(span0, (512 * 1024) as u64);
        assert_eq!(span1, (512 * 1024) as u64);
    }

    #[test]
    fn load_cached_chunk_rejects_non_zstd_metadata() {
        let temp = tempdir().unwrap();
        let cache_root = temp.path();
        let key = "chunks/aa/bb/test";
        let hash = "blake3:test-hash";

        let (data_path, meta_path) = chunk_cache_paths(cache_root, key).unwrap();
        fs::create_dir_all(data_path.parent().unwrap()).unwrap();
        fs::write(&data_path, vec![0u8; 4]).unwrap();

        let bad_metadata = CachedChunkMetadata {
            digest: hash.to_string(),
            compression: Cow::Owned("lz4".to_string()),
            uncompressed_size: 4,
            compressed_size: 4,
            compressed_hash: "blake3:deadbeef".to_string(),
        };
        let payload = serde_json::to_vec(&bad_metadata).unwrap();
        fs::write(&meta_path, payload).unwrap();

        let result = load_cached_chunk(cache_root, key, hash, 4).unwrap();
        assert!(result.is_none(), "non-zstd metadata should be rejected");
        assert!(
            !data_path.exists() && !meta_path.exists(),
            "invalid metadata should be invalidated from cache"
        );
    }

    #[test]
    fn load_cached_chunk_accepts_zstd_metadata() {
        let temp = tempdir().unwrap();
        let cache_root = temp.path();
        let key = "chunks/aa/bb/good";
        let hash = "blake3:good-hash";

        let (data_path, meta_path) = chunk_cache_paths(cache_root, key).unwrap();
        fs::create_dir_all(data_path.parent().unwrap()).unwrap();
        fs::write(&data_path, vec![1u8; 8]).unwrap();

        let metadata = CachedChunkMetadata {
            digest: hash.to_string(),
            compression: Cow::Borrowed(CHUNK_COMPRESSION),
            uncompressed_size: 8,
            compressed_size: 8,
            compressed_hash: "blake3:cafef00d".to_string(),
        };
        write_cached_chunk_metadata(&meta_path, &metadata).unwrap();

        let record = load_cached_chunk(cache_root, key, hash, 8).unwrap();
        let record = record.expect("zstd metadata should be accepted");
        assert_eq!(record.compressed_size, 8);
        assert_eq!(record.compressed_hash, "blake3:cafef00d");
    }
}

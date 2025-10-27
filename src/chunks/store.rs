use crate::platform::SystemResources;
use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Debug, Clone, Copy)]
pub enum StoreKind {
    Memory,
    Disk,
}

pub fn choose_store(total_uncompressed: u64) -> (StoreKind, u64) {
    let max_ram_mb = std::env::var("BORINGCACHE_MAX_RAM_MB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2048);
    let cap = (max_ram_mb as u64) * 1024 * 1024;

    if total_uncompressed <= cap {
        (StoreKind::Memory, cap)
    } else {
        (StoreKind::Disk, cap)
    }
}

pub fn get_download_concurrency() -> usize {
    if let Ok(raw) = std::env::var("BORINGCACHE_DOWNLOAD_CONCURRENCY") {
        if let Ok(value) = raw.parse::<usize>() {
            return value.clamp(1, 32);
        }
    }

    let resources = SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();
    resources
        .recommended_download_concurrency(is_ci)
        .clamp(1, 16)
}

pub fn get_write_concurrency() -> usize {
    let default = (num_cpus::get().saturating_mul(2)).clamp(4, 16);

    std::env::var("BORINGCACHE_WRITE_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .clamp(2, 32)
}

#[async_trait::async_trait]
pub trait ChunkStore: Send + Sync {
    async fn put(&self, digest: &str, data: Vec<u8>) -> Result<()>;
    async fn read_range(&self, digest: &str, offset: u64, length: u64) -> Result<Vec<u8>>;
    fn size_of(&self, digest: &str) -> Option<u64>;
    async fn finalize(self: Box<Self>) -> Result<()>;
}

pub struct MemoryStore {
    map: DashMap<String, Bytes>,
    current_bytes: AtomicU64,
    max_bytes: u64,
}

impl MemoryStore {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            map: DashMap::new(),
            current_bytes: AtomicU64::new(0),
            max_bytes,
        }
    }

    fn check_capacity(&self, size: u64) -> Result<()> {
        let current = self.current_bytes.load(Ordering::Relaxed);
        if current + size > self.max_bytes {
            anyhow::bail!(
                "Memory store capacity exceeded: {} + {} > {}",
                current,
                size,
                self.max_bytes
            );
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ChunkStore for MemoryStore {
    async fn put(&self, digest: &str, data: Vec<u8>) -> Result<()> {
        let size = data.len() as u64;
        self.check_capacity(size)?;

        self.map.insert(digest.to_string(), Bytes::from(data));
        self.current_bytes.fetch_add(size, Ordering::Relaxed);
        Ok(())
    }

    async fn read_range(&self, digest: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        let entry = self
            .map
            .get(digest)
            .ok_or_else(|| anyhow::anyhow!("Chunk not found in memory store: {}", digest))?;

        let start = offset as usize;
        let end = (offset + length) as usize;

        if end > entry.len() {
            anyhow::bail!(
                "Read range out of bounds: {}..{} for chunk of size {}",
                start,
                end,
                entry.len()
            );
        }

        Ok(entry.slice(start..end).to_vec())
    }

    fn size_of(&self, digest: &str) -> Option<u64> {
        self.map.get(digest).map(|v| v.len() as u64)
    }

    async fn finalize(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}

pub struct DiskStore {
    root: PathBuf,
    sizes: DashMap<String, u64>,
}

impl DiskStore {
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("Failed to create disk store directory: {:?}", root))?;
        Ok(Self {
            root,
            sizes: DashMap::new(),
        })
    }

    fn sanitize_digest(digest: &str) -> String {
        digest.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
    }

    fn chunk_path(&self, digest: &str) -> PathBuf {
        let safe_name = Self::sanitize_digest(digest);
        self.root.join(safe_name)
    }
}

#[async_trait::async_trait]
impl ChunkStore for DiskStore {
    async fn put(&self, digest: &str, data: Vec<u8>) -> Result<()> {
        let size = data.len() as u64;
        let path = self.chunk_path(digest);
        let temp_path = path.with_extension("tmp");

        let mut file = tokio::fs::File::create(&temp_path)
            .await
            .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;

        file.write_all(&data)
            .await
            .context("Failed to write chunk data")?;

        file.sync_all().await.context("Failed to sync chunk")?;

        tokio::fs::rename(&temp_path, &path)
            .await
            .with_context(|| format!("Failed to rename temp file to {:?}", path))?;

        self.sizes.insert(digest.to_string(), size);
        Ok(())
    }

    async fn read_range(&self, digest: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        let path = self.chunk_path(digest);
        let mut file = tokio::fs::File::open(&path)
            .await
            .with_context(|| format!("Failed to open chunk file: {:?}", path))?;

        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .context("Failed to seek in chunk file")?;

        let mut buf = vec![0u8; length as usize];
        file.read_exact(&mut buf)
            .await
            .context("Failed to read chunk range")?;

        Ok(buf)
    }

    fn size_of(&self, digest: &str) -> Option<u64> {
        self.sizes.get(digest).map(|v| *v)
    }

    async fn finalize(self: Box<Self>) -> Result<()> {
        tokio::fs::remove_dir_all(&self.root)
            .await
            .with_context(|| format!("Failed to cleanup disk store: {:?}", self.root))?;
        Ok(())
    }
}

pub enum AnyStore {
    Mem(Arc<MemoryStore>),
    Disk(Arc<DiskStore>),
}

impl Clone for AnyStore {
    fn clone(&self) -> Self {
        match self {
            Self::Mem(s) => Self::Mem(s.clone()),
            Self::Disk(s) => Self::Disk(s.clone()),
        }
    }
}

impl AnyStore {
    pub async fn new_for(total_uncompressed: u64) -> Result<Self> {
        let (kind, cap) = choose_store(total_uncompressed);
        match kind {
            StoreKind::Memory => Ok(Self::Mem(Arc::new(MemoryStore::new(cap)))),
            StoreKind::Disk => {
                let dir = std::env::temp_dir()
                    .join("boringcache")
                    .join("chunks")
                    .join(nanoid::nanoid!());
                tokio::fs::create_dir_all(&dir).await?;

                let size_gb = (total_uncompressed as f64) / (1024.0 * 1024.0 * 1024.0);
                crate::ui::info(&format!(
                    "Using disk-backed chunk store at {} (planned ~{:.1} GB)",
                    dir.display(),
                    size_gb
                ));

                Ok(Self::Disk(Arc::new(DiskStore::new(dir)?)))
            }
        }
    }

    pub fn kind(&self) -> StoreKind {
        match self {
            Self::Mem(_) => StoreKind::Memory,
            Self::Disk(_) => StoreKind::Disk,
        }
    }
}

#[async_trait::async_trait]
impl ChunkStore for AnyStore {
    async fn put(&self, digest: &str, data: Vec<u8>) -> Result<()> {
        match self {
            Self::Mem(s) => s.put(digest, data).await,
            Self::Disk(s) => s.put(digest, data).await,
        }
    }

    async fn read_range(&self, digest: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        match self {
            Self::Mem(s) => s.read_range(digest, offset, length).await,
            Self::Disk(s) => s.read_range(digest, offset, length).await,
        }
    }

    fn size_of(&self, digest: &str) -> Option<u64> {
        match self {
            Self::Mem(s) => s.size_of(digest),
            Self::Disk(s) => s.size_of(digest),
        }
    }

    async fn finalize(self: Box<Self>) -> Result<()> {
        match *self {
            Self::Mem(s) => {
                let s: Box<dyn ChunkStore> = Box::new(
                    Arc::try_unwrap(s).unwrap_or_else(|arc| MemoryStore::new(arc.max_bytes)),
                );
                s.finalize().await
            }
            Self::Disk(s) => {
                let s: Box<dyn ChunkStore> = Box::new(
                    Arc::try_unwrap(s)
                        .unwrap_or_else(|arc| DiskStore::new(arc.root.clone()).unwrap()),
                );
                s.finalize().await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryStore::new(1024 * 1024);
        let data = vec![1, 2, 3, 4, 5];
        store.put("test", data.clone()).await.unwrap();

        assert_eq!(store.size_of("test"), Some(5));

        let range = store.read_range("test", 1, 3).await.unwrap();
        assert_eq!(range, vec![2, 3, 4]);
    }

    #[tokio::test]
    async fn test_disk_store() {
        let dir = std::env::temp_dir()
            .join("boringcache_test")
            .join(nanoid::nanoid!());
        let store = DiskStore::new(dir.clone()).unwrap();

        let data = vec![10, 20, 30, 40, 50];
        store.put("test", data.clone()).await.unwrap();

        assert_eq!(store.size_of("test"), Some(5));

        let range = store.read_range("test", 2, 2).await.unwrap();
        assert_eq!(range, vec![30, 40]);

        Box::new(store).finalize().await.unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_choose_store() {
        std::env::remove_var("BORINGCACHE_MAX_RAM_MB");
        let (kind, cap) = choose_store(1024 * 1024 * 1024);
        assert!(matches!(kind, StoreKind::Memory));
        assert_eq!(cap, 2048 * 1024 * 1024);

        let (kind, _) = choose_store(3 * 1024 * 1024 * 1024);
        assert!(matches!(kind, StoreKind::Disk));
    }
}

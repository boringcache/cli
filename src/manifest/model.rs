use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    pub tag: String,
    pub root: ManifestRoot,
    pub summary: ManifestSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<ManifestEntryMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<ManifestArchive>,
    #[serde(alias = "entries")]
    pub files: Vec<ManifestFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<ChunkMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<ManifestPack>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRoot {
    pub digest: String,
    pub algo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSummary {
    pub file_count: u64,
    pub raw_size: u64,
    pub changed_count: u64,
    pub removed_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntryMetadata {
    pub workspace: String,
    pub entry_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestArchive {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub compression: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    pub size: u64,
    pub mode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spans: Option<Vec<ChunkSpan>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub state: EntryState,
    // New storage model for small-file packs or explicit chunk spans
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<FileStorage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkSpan {
    pub digest: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub digest: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    pub offset: u64,
    pub size: u64,
    pub hash: String,
    pub key: String,
}

// Storage for a file: either explicit chunk spans or located inside a pack
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "storage", rename_all = "lowercase")]
pub enum FileStorage {
    Chunks {
        spans: Vec<ChunkSpan>,
    },
    Pack {
        pack_id: String,
        offset: u64,
        length: u64,
    },
}

// A pack is a virtual stream assembled from chunk spans; used for many small files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPack {
    pub pack_id: String,
    pub spans: Vec<ChunkSpan>,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
}

pub type ManifestEntry = ManifestFile;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntryType {
    File,
    Dir,
    Symlink,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntryState {
    Present,
    Removed,
}

impl EntryType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryType::File => "file",
            EntryType::Dir => "dir",
            EntryType::Symlink => "symlink",
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            EntryType::File => 1,
            EntryType::Dir => 2,
            EntryType::Symlink => 3,
        }
    }
}

impl EntryState {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryState::Present => "present",
            EntryState::Removed => "removed",
        }
    }
}

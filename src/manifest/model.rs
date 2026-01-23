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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_hint: Option<String>,
    pub encrypted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_name: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub state: EntryState,
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

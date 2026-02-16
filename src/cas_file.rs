use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const FORMAT_VERSION: u32 = 1;
const ADAPTER: &str = "file-v1";

#[derive(Debug, Clone)]
pub struct FileBlobSource {
    pub digest: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FileLayoutScan {
    pub entries: Vec<FilePointerEntry>,
    pub blobs: Vec<FileBlobSource>,
    pub total_blob_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePointerBlob {
    pub digest: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePointerEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: crate::manifest::EntryType,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePointer {
    pub format_version: u32,
    pub adapter: String,
    pub entries: Vec<FilePointerEntry>,
    pub blobs: Vec<FilePointerBlob>,
}

pub fn scan_path(path: &Path, exclude_patterns: Vec<String>) -> Result<FileLayoutScan> {
    let root = path.to_path_buf();
    let root_is_file = root.is_file();
    let draft = crate::manifest::ManifestBuilder::new(&root)
        .with_exclude_patterns(exclude_patterns)
        .build()?;

    let mut blob_by_digest: HashMap<String, FileBlobSource> = HashMap::new();
    let mut entries = Vec::with_capacity(draft.descriptors.len());

    for descriptor in draft.descriptors {
        let (digest, size_bytes) = if descriptor.entry_type == crate::manifest::EntryType::File {
            let absolute_path = if root_is_file {
                root.clone()
            } else {
                root.join(&descriptor.path)
            };
            let digest_hex = sha256_hex_file(&absolute_path)?;
            let digest = format!("sha256:{digest_hex}");
            let size_bytes = descriptor.size;

            match blob_by_digest.get(&digest) {
                Some(existing) => {
                    if existing.size_bytes != size_bytes {
                        return Err(anyhow!(
                            "Digest collision with size mismatch for {}",
                            absolute_path.display()
                        ));
                    }
                }
                None => {
                    blob_by_digest.insert(
                        digest.clone(),
                        FileBlobSource {
                            digest: digest.clone(),
                            size_bytes,
                            path: absolute_path,
                        },
                    );
                }
            }

            (Some(digest), size_bytes)
        } else {
            (None, 0)
        };

        entries.push(FilePointerEntry {
            path: descriptor.path,
            entry_type: descriptor.entry_type,
            size_bytes,
            executable: descriptor.executable,
            target: descriptor.target,
            digest,
        });
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut blobs = blob_by_digest.into_values().collect::<Vec<_>>();
    blobs.sort_by(|left, right| left.digest.cmp(&right.digest));
    let total_blob_bytes = blobs.iter().map(|blob| blob.size_bytes).sum();

    Ok(FileLayoutScan {
        entries,
        blobs,
        total_blob_bytes,
    })
}

pub fn build_pointer(scan: &FileLayoutScan) -> Result<Vec<u8>> {
    let pointer = FilePointer {
        format_version: FORMAT_VERSION,
        adapter: ADAPTER.to_string(),
        entries: scan.entries.clone(),
        blobs: scan
            .blobs
            .iter()
            .map(|blob| FilePointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            })
            .collect(),
    };

    serde_json::to_vec(&pointer).context("Failed to serialize file CAS pointer")
}

pub fn parse_pointer(bytes: &[u8]) -> Result<FilePointer> {
    let pointer: FilePointer =
        serde_json::from_slice(bytes).context("Failed to parse file CAS pointer")?;

    if pointer.format_version != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported file CAS pointer version {}",
            pointer.format_version
        ));
    }
    if pointer.adapter != ADAPTER {
        return Err(anyhow!(
            "Unsupported file CAS pointer adapter '{}'",
            pointer.adapter
        ));
    }

    let mut blob_sizes = HashMap::new();
    for blob in &pointer.blobs {
        if !crate::cas_oci::is_valid_sha256_digest(&blob.digest) {
            return Err(anyhow!("Invalid file CAS blob digest '{}'", blob.digest));
        }
        blob_sizes.insert(blob.digest.as_str(), blob.size_bytes);
    }

    for entry in &pointer.entries {
        validate_relative_path(&entry.path)?;
        match entry.entry_type {
            crate::manifest::EntryType::File => {
                let digest = entry.digest.as_ref().ok_or_else(|| {
                    anyhow!("File CAS entry {} missing digest", entry.path.as_str())
                })?;
                if !crate::cas_oci::is_valid_sha256_digest(digest) {
                    return Err(anyhow!(
                        "Invalid file CAS entry digest '{}' for {}",
                        digest,
                        entry.path
                    ));
                }
                let blob_size = blob_sizes.get(digest.as_str()).ok_or_else(|| {
                    anyhow!(
                        "File CAS pointer missing blob metadata for digest {}",
                        digest
                    )
                })?;
                if entry.size_bytes != *blob_size {
                    return Err(anyhow!(
                        "File CAS size mismatch for {} (entry {}, blob {})",
                        entry.path,
                        entry.size_bytes,
                        blob_size
                    ));
                }
            }
            crate::manifest::EntryType::Dir => {}
            crate::manifest::EntryType::Symlink => {
                if entry.target.is_none() {
                    return Err(anyhow!(
                        "File CAS symlink entry {} missing target",
                        entry.path
                    ));
                }
            }
        }
    }

    Ok(pointer)
}

pub fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    Ok(root.join(Path::new(relative)))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{:02x}", byte);
    }
    output
}

pub fn prefixed_sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

pub fn digest_matches(expected: &str, actual_hex: &str) -> bool {
    expected == format!("sha256:{actual_hex}")
}

fn validate_relative_path(relative: &str) -> Result<()> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute() {
        return Err(anyhow!("Absolute path is not allowed: {}", relative));
    }
    for component in relative_path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(anyhow!(
                    "File CAS pointer contains unsupported path component: {}",
                    relative
                ));
            }
        }
    }
    Ok(())
}

fn sha256_hex_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open {} for hashing", path.display()))?;
    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{:02x}", byte);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_pointer_round_trip_works() {
        let scan = FileLayoutScan {
            entries: vec![FilePointerEntry {
                path: "a.txt".to_string(),
                entry_type: crate::manifest::EntryType::File,
                size_bytes: 3,
                executable: Some(false),
                target: None,
                digest: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
            }],
            blobs: vec![FileBlobSource {
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size_bytes: 3,
                path: PathBuf::from("/tmp/blob"),
            }],
            total_blob_bytes: 3,
        };

        let pointer_bytes = build_pointer(&scan).unwrap();
        let pointer = parse_pointer(&pointer_bytes).unwrap();
        assert_eq!(pointer.entries.len(), 1);
        assert_eq!(pointer.blobs.len(), 1);
    }

    #[test]
    fn safe_join_rejects_parent_component() {
        let root = PathBuf::from("/tmp/root");
        let error = safe_join(&root, "../x").unwrap_err().to_string();
        assert!(error.contains("unsupported path component"));
    }
}

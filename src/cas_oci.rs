use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FORMAT_VERSION: u32 = 1;
const ADAPTER: &str = "oci-v1";
const SHA256_PREFIX: &str = "sha256:";
const DEFAULT_OCI_LAYOUT: &str = r#"{"imageLayoutVersion":"1.0.0"}"#;

#[derive(Debug, Clone)]
pub struct OciBlobFile {
    pub digest: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct OciLayoutScan {
    pub index_json: Vec<u8>,
    pub oci_layout: Vec<u8>,
    pub blobs: Vec<OciBlobFile>,
    pub total_blob_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPointerBlob {
    pub digest: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPointer {
    pub format_version: u32,
    pub adapter: String,
    pub index_json_base64: String,
    pub oci_layout_base64: String,
    pub blobs: Vec<OciPointerBlob>,
}

impl OciPointer {
    pub fn index_json_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.index_json_base64.as_bytes())
            .context("Invalid base64 payload for index_json_base64")
    }

    pub fn oci_layout_bytes(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.oci_layout_base64.as_bytes())
            .context("Invalid base64 payload for oci_layout_base64")
    }
}

pub fn scan_layout(path: &Path) -> Result<OciLayoutScan> {
    let index_path = path.join("index.json");
    let blobs_path = path.join("blobs").join("sha256");
    if !index_path.is_file() {
        return Err(anyhow!(
            "Missing OCI index at {}",
            index_path.to_string_lossy()
        ));
    }
    if !blobs_path.is_dir() {
        return Err(anyhow!(
            "Missing OCI blobs directory at {}",
            blobs_path.to_string_lossy()
        ));
    }

    let index_json = std::fs::read(&index_path)
        .with_context(|| format!("Failed to read {}", index_path.display()))?;
    let oci_layout_path = path.join("oci-layout");
    let oci_layout = if oci_layout_path.is_file() {
        std::fs::read(&oci_layout_path)
            .with_context(|| format!("Failed to read {}", oci_layout_path.display()))?
    } else {
        DEFAULT_OCI_LAYOUT.as_bytes().to_vec()
    };

    let mut blobs = Vec::new();
    for entry in std::fs::read_dir(&blobs_path)
        .with_context(|| format!("Failed to read {}", blobs_path.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !is_valid_sha256_hex(&file_name) {
            continue;
        }
        let digest = format!("{}{}", SHA256_PREFIX, file_name.to_ascii_lowercase());
        let path = entry.path();
        let size_bytes = entry
            .metadata()
            .with_context(|| format!("Failed to stat {}", path.display()))?
            .len();

        blobs.push(OciBlobFile {
            digest,
            size_bytes,
            path,
        });
    }

    blobs.sort_by(|left, right| left.digest.cmp(&right.digest));
    let total_blob_bytes = blobs.iter().map(|blob| blob.size_bytes).sum();

    Ok(OciLayoutScan {
        index_json,
        oci_layout,
        blobs,
        total_blob_bytes,
    })
}

pub fn build_pointer(scan: &OciLayoutScan) -> Result<Vec<u8>> {
    let pointer = OciPointer {
        format_version: FORMAT_VERSION,
        adapter: ADAPTER.to_string(),
        index_json_base64: STANDARD.encode(&scan.index_json),
        oci_layout_base64: STANDARD.encode(&scan.oci_layout),
        blobs: scan
            .blobs
            .iter()
            .map(|blob| OciPointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            })
            .collect(),
    };

    serde_json::to_vec(&pointer).context("Failed to serialize OCI CAS pointer")
}

pub fn parse_pointer(bytes: &[u8]) -> Result<OciPointer> {
    let pointer: OciPointer =
        serde_json::from_slice(bytes).context("Failed to parse OCI CAS pointer")?;

    if pointer.format_version != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported OCI CAS pointer version {}",
            pointer.format_version
        ));
    }
    if pointer.adapter != ADAPTER {
        return Err(anyhow!(
            "Unsupported OCI CAS pointer adapter '{}'",
            pointer.adapter
        ));
    }

    let _ = pointer.index_json_bytes()?;
    let _ = pointer.oci_layout_bytes()?;

    for blob in &pointer.blobs {
        if !is_valid_sha256_digest(&blob.digest) {
            return Err(anyhow!("Invalid OCI blob digest '{}'", blob.digest));
        }
    }

    Ok(pointer)
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
    format!("{SHA256_PREFIX}{}", sha256_hex(bytes))
}

pub fn digest_matches(expected: &str, actual_hex: &str) -> bool {
    expected == format!("{SHA256_PREFIX}{actual_hex}")
}

pub fn digest_hex_component(digest: &str) -> Option<&str> {
    digest.strip_prefix(SHA256_PREFIX)
}

pub fn is_valid_sha256_digest(digest: &str) -> bool {
    if let Some(hex) = digest.strip_prefix(SHA256_PREFIX) {
        return is_valid_sha256_hex(hex);
    }
    false
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_layout_collects_blobs() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("blobs").join("sha256")).unwrap();
        std::fs::write(temp.path().join("index.json"), "{}").unwrap();
        std::fs::write(
            temp.path()
                .join("blobs")
                .join("sha256")
                .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            b"abc",
        )
        .unwrap();

        let scan = scan_layout(temp.path()).unwrap();
        assert_eq!(scan.blobs.len(), 1);
        assert_eq!(
            scan.blobs[0].digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(scan.total_blob_bytes, 3);
    }

    #[test]
    fn pointer_round_trip_works() {
        let scan = OciLayoutScan {
            index_json: b"{\"schemaVersion\":2}".to_vec(),
            oci_layout: DEFAULT_OCI_LAYOUT.as_bytes().to_vec(),
            blobs: vec![OciBlobFile {
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size_bytes: 12,
                path: PathBuf::from("/tmp/blob"),
            }],
            total_blob_bytes: 12,
        };

        let bytes = build_pointer(&scan).unwrap();
        let pointer = parse_pointer(&bytes).unwrap();
        assert_eq!(pointer.format_version, FORMAT_VERSION);
        assert_eq!(pointer.adapter, ADAPTER);
        assert_eq!(pointer.blobs.len(), 1);
    }

    #[test]
    fn digest_helpers_handle_prefixed_values() {
        let bytes = b"hello";
        let hex = sha256_hex(bytes);
        let prefixed = prefixed_sha256_digest(bytes);
        assert!(!digest_matches(&hex, &hex));
        assert!(digest_matches(&prefixed, &hex));
        assert_eq!(digest_hex_component(&prefixed), Some(hex.as_str()));
    }
}

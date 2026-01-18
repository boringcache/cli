use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::model::Manifest;

pub type ManifestIoError = anyhow::Error;

pub async fn save_manifest(manifest: &Manifest, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create manifest directory {}", parent.display()))?;
    }

    let mut buffer = Vec::new();
    ciborium::ser::into_writer(manifest, &mut buffer)
        .context("Failed to serialize manifest to CBOR")?;

    tokio::fs::write(path, buffer)
        .await
        .with_context(|| format!("Failed to write manifest file {}", path.display()))
}

pub async fn load_manifest(path: &Path) -> Result<Manifest> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to read manifest from {}", path.display()))?;
    decode_manifest(&bytes)
}

pub fn decode_manifest(bytes: &[u8]) -> Result<Manifest> {
    ciborium::de::from_reader(bytes).context("Failed to decode manifest data")
}

pub fn encode_manifest(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(manifest, &mut buffer)
        .context("Failed to encode manifest to CBOR")?;
    Ok(buffer)
}

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

pub fn compress_manifest(cbor_bytes: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(cbor_bytes, 3).context("Failed to compress manifest with zstd")
}

pub fn decompress_manifest_if_needed(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() >= 4 && bytes[0..4] == ZSTD_MAGIC {
        zstd::decode_all(bytes).context("Failed to decompress manifest")
    } else {
        Ok(bytes.to_vec())
    }
}

pub fn compute_manifest_digest(manifest_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(manifest_bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{:02x}", byte);
    }
    output
}

use std::path::Path;

use anyhow::{Context, Result};

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

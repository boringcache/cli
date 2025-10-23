use std::path::PathBuf;

use anyhow::{Context, Result};

use super::model::Manifest;

pub struct ManifestCache {
    cache_dir: PathBuf,
}

impl ManifestCache {
    pub fn new() -> Result<Self> {
        let home_dir = crate::config::Config::home_dir()?;
        let cache_dir = home_dir.join(".boringcache").join("manifests");
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!("Failed to create manifest cache directory: {:?}", cache_dir)
        })?;
        Ok(Self { cache_dir })
    }

    fn manifest_path(&self, workspace: &str, tag: &str) -> PathBuf {
        let safe_workspace = sanitize_filename(workspace);
        let safe_tag = sanitize_filename(tag);
        self.cache_dir
            .join(&safe_workspace)
            .join(format!("{}.cbor", safe_tag))
    }

    pub async fn get(&self, workspace: &str, tag: &str) -> Option<Manifest> {
        let path = self.manifest_path(workspace, tag);
        if !path.exists() {
            return None;
        }

        super::io::load_manifest(&path).await.ok()
    }

    pub async fn put(&self, workspace: &str, tag: &str, manifest: &Manifest) -> Result<()> {
        let path = self.manifest_path(workspace, tag);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create manifest directory: {:?}", parent))?;
        }
        super::io::save_manifest(manifest, &path).await
    }

    pub fn clear_tag(&self, workspace: &str, tag: &str) -> Result<()> {
        let path = self.manifest_path(workspace, tag);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove cached manifest: {:?}", path))?;
        }
        Ok(())
    }
}

fn sanitize_filename(name: &str) -> String {
    name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
}

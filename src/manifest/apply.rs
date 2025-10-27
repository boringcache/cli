use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use super::model::{EntryState, EntryType, Manifest};

pub struct ManifestApplier;

impl ManifestApplier {
    pub async fn apply(manifest: &Manifest, root: &Path) -> Result<()> {
        for entry in &manifest.files {
            let target_path = sanitized_join(root, &entry.path)?;

            match entry.state {
                EntryState::Removed => {
                    remove_entry(&target_path, entry.entry_type).await?;
                }
                EntryState::Present => {
                    if entry.entry_type == EntryType::Dir {
                        tokio::fs::create_dir_all(&target_path).await.ok();
                    }
                    #[cfg(unix)]
                    set_mode(&target_path, entry.mode, entry.entry_type).await?;
                }
            }
        }

        Ok(())
    }
}

async fn remove_entry(path: &Path, entry_type: EntryType) -> Result<()> {
    match entry_type {
        EntryType::Dir => {
            if tokio::fs::remove_dir_all(path).await.is_err() {
                if let Err(err) = tokio::fs::remove_dir(path).await {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        return Err(err).with_context(|| {
                            format!("Failed to remove directory {}", path.display())
                        });
                    }
                }
            }
        }
        _ => {
            if let Err(err) = tokio::fs::remove_file(path).await {
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(err)
                        .with_context(|| format!("Failed to remove entry {}", path.display()));
                }
            }
        }
    }

    Ok(())
}

fn sanitized_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative_path = Path::new(relative);
    for component in relative_path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(anyhow!(
                    "Manifest entry contains unsupported path component: {}",
                    relative
                ));
            }
        }
    }

    Ok(root.join(relative_path))
}

#[cfg(unix)]
async fn set_mode(path: &Path, mode: u32, entry_type: EntryType) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if entry_type == EntryType::Symlink {
        return Ok(());
    }

    let permissions = std::fs::Permissions::from_mode(mode);

    if let Err(err) = tokio::fs::set_permissions(path, permissions).await {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err)
                .with_context(|| format!("Failed to set permissions for {}", path.display()));
        }
    }

    Ok(())
}

#[cfg(not(unix))]
async fn set_mode(_path: &Path, _mode: u32, _entry_type: EntryType) -> Result<()> {
    Ok(())
}

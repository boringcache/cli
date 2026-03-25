use anyhow::{Context, Result};
use std::io::ErrorKind;
use std::path::Path;
use tokio::fs;

pub(crate) async fn remove_path_if_exists(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                fs::remove_dir_all(path)
                    .await
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
            } else {
                fs::remove_file(path)
                    .await
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

pub(crate) async fn create_symlink(path: &Path, target: String) -> Result<()> {
    let destination = path.to_path_buf();
    tokio::task::spawn_blocking(move || create_symlink_blocking(&destination, &target))
        .await
        .context("Symlink task panicked")?
}

#[cfg(unix)]
fn create_symlink_blocking(path: &Path, target: &str) -> Result<()> {
    std::os::unix::fs::symlink(target, path)
        .with_context(|| format!("Failed to create symlink {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn create_symlink_blocking(path: &Path, target: &str) -> Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    if symlink_file(target, path).is_err() {
        symlink_dir(target, path)
            .with_context(|| format!("Failed to create symlink {}", path.display()))?;
    }
    Ok(())
}

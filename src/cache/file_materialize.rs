use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Semaphore;

#[derive(Clone)]
struct FileMaterializeJob {
    destination: PathBuf,
    source_blob: PathBuf,
    executable: bool,
}

#[derive(Clone)]
struct FileLinkJob {
    destination: PathBuf,
    primary_destination: PathBuf,
    source_blob: PathBuf,
    executable: bool,
}

pub(crate) async fn materialize_file_cas_entries(
    target_root: &Path,
    entries: &[crate::cas_file::FilePointerEntry],
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<()> {
    fs::create_dir_all(target_root)
        .await
        .with_context(|| format!("Failed to create {}", target_root.display()))?;

    for entry in entries {
        if entry.entry_type != crate::manifest::EntryType::Dir {
            continue;
        }

        let destination = crate::cas_file::safe_join(target_root, &entry.path)?;
        remove_path_if_exists(&destination).await?;
        fs::create_dir_all(&destination)
            .await
            .with_context(|| format!("Failed to create {}", destination.display()))?;
    }

    let mut primary_jobs = Vec::new();
    let mut link_jobs = Vec::new();
    let mut symlink_jobs = Vec::new();
    let mut primary_by_key: HashMap<(String, bool), PathBuf> = HashMap::new();

    for entry in entries {
        match entry.entry_type {
            crate::manifest::EntryType::Dir => {}
            crate::manifest::EntryType::File => {
                let destination = crate::cas_file::safe_join(target_root, &entry.path)?;
                let digest = entry
                    .digest
                    .as_ref()
                    .ok_or_else(|| anyhow!("File entry missing digest for {}", entry.path))?;
                let source_blob = blob_path_by_digest
                    .get(digest)
                    .cloned()
                    .ok_or_else(|| anyhow!("Missing downloaded blob for digest {}", digest))?;
                let executable = entry.executable == Some(true);
                let key = (digest.clone(), executable);

                if let Some(primary_destination) = primary_by_key.get(&key) {
                    link_jobs.push(FileLinkJob {
                        destination,
                        primary_destination: primary_destination.clone(),
                        source_blob,
                        executable,
                    });
                } else {
                    primary_by_key.insert(key, destination.clone());
                    primary_jobs.push(FileMaterializeJob {
                        destination,
                        source_blob,
                        executable,
                    });
                }
            }
            crate::manifest::EntryType::Symlink => {
                let destination = crate::cas_file::safe_join(target_root, &entry.path)?;
                let link_target = entry
                    .target
                    .as_ref()
                    .ok_or_else(|| anyhow!("Symlink entry missing target for {}", entry.path))?
                    .clone();
                crate::cas_file::validate_symlink_target(
                    target_root,
                    &destination,
                    Path::new(&link_target),
                    allow_external_symlinks,
                )?;
                symlink_jobs.push((destination, link_target));
            }
        }
    }

    let file_job_count = primary_jobs.len().max(link_jobs.len()).max(1);
    let max_concurrent = crate::command_support::get_optimal_concurrency(file_job_count, "restore");
    let semaphore = Arc::new(Semaphore::new(max_concurrent.max(1)));

    let mut primary_tasks = Vec::with_capacity(primary_jobs.len());
    for job in primary_jobs {
        let semaphore = semaphore.clone();
        primary_tasks.push(tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow!("Restore materialize semaphore closed: {error}"))?;
            let result = materialize_primary_file(job).await;
            drop(_permit);
            result
        }));
    }
    for task in primary_tasks {
        task.await.context("Primary materialize task panicked")??;
    }

    let mut link_tasks = Vec::with_capacity(link_jobs.len());
    for job in link_jobs {
        let semaphore = semaphore.clone();
        link_tasks.push(tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow!("Restore materialize semaphore closed: {error}"))?;
            let result = materialize_link_file(job).await;
            drop(_permit);
            result
        }));
    }
    for task in link_tasks {
        task.await.context("Link materialize task panicked")??;
    }

    for (destination, link_target) in symlink_jobs {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        remove_path_if_exists(&destination).await?;
        create_symlink(&destination, link_target).await?;
    }

    Ok(())
}

async fn materialize_primary_file(job: FileMaterializeJob) -> Result<()> {
    if let Some(parent) = job.destination.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    remove_path_if_exists(&job.destination).await?;
    fs::copy(&job.source_blob, &job.destination)
        .await
        .with_context(|| {
            format!(
                "Failed to materialize {} from {}",
                job.destination.display(),
                job.source_blob.display()
            )
        })?;
    apply_executable_permissions(&job.destination, job.executable).await
}

async fn materialize_link_file(job: FileLinkJob) -> Result<()> {
    if let Some(parent) = job.destination.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    remove_path_if_exists(&job.destination).await?;
    match fs::hard_link(&job.primary_destination, &job.destination).await {
        Ok(_) => Ok(()),
        Err(_) => {
            fs::copy(&job.source_blob, &job.destination)
                .await
                .with_context(|| {
                    format!(
                        "Failed to materialize {} from {}",
                        job.destination.display(),
                        job.source_blob.display()
                    )
                })?;
            apply_executable_permissions(&job.destination, job.executable).await
        }
    }
}

#[cfg(unix)]
async fn apply_executable_permissions(path: &Path, executable: bool) -> Result<()> {
    if executable {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).await?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(path, perms).await?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn apply_executable_permissions(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn remove_path_if_exists_ignores_missing_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing");
        remove_path_if_exists(&missing).await.unwrap();
    }
}

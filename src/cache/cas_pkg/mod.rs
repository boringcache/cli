mod pointer;
mod tar;

use anyhow::{Context, Result, anyhow};
pub use pointer::{
    ADAPTER, FORMAT_VERSION, PkgCompatibility, PkgFixup, PkgPointer, PkgPointerBlob,
    PkgPointerPackage, build_pointer, parse_pointer,
};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::BufReader;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::task::JoinSet;
use zstd::stream::read::Decoder as ZstdDecoder;

#[derive(Debug, Clone)]
pub struct PkgBlobSource {
    pub digest: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct PkgLayoutScan {
    pub ecosystem: String,
    pub compatibility: Option<PkgCompatibility>,
    pub packages: Vec<PkgPointerPackage>,
    pub fixups: Vec<PkgFixup>,
    pub blobs: Vec<PkgBlobSource>,
    pub total_blob_bytes: u64,
    pub temp_dir: TempDir,
}

#[derive(Debug, Clone)]
struct CoveredPath {
    absolute: PathBuf,
    is_dir: bool,
}

pub fn scan_packages(
    root: &Path,
    ecosystem: &str,
    compatibility: Option<PkgCompatibility>,
    packages: &[crate::pkg_adapters::ResolvedPackage],
) -> Result<PkgLayoutScan> {
    let temp_dir = tempfile::tempdir().context("Failed to create package CAS temp directory")?;
    let mut blob_by_digest: BTreeMap<String, PkgBlobSource> = BTreeMap::new();
    let mut pointer_packages = Vec::new();
    let mut covered_paths = Vec::new();

    let mut packages = packages.to_vec();
    packages.sort_by(|left, right| left.package_key.cmp(&right.package_key));

    for (index, package) in packages.iter().enumerate() {
        let tar_path = temp_dir.path().join(format!("package-{index}.tar.zst"));
        let package_tar = tar::write_package_tar(root, &package.install_paths, &tar_path)
            .with_context(|| format!("Failed to package {}", package.package_key))?;
        if package_tar.entry_count == 0 {
            continue;
        }

        blob_by_digest
            .entry(package_tar.digest.clone())
            .or_insert_with(|| PkgBlobSource {
                digest: package_tar.digest.clone(),
                size_bytes: package_tar.size_bytes,
                path: tar_path.clone(),
            });

        let mut install_paths = Vec::with_capacity(package.install_paths.len());
        for install_path in &package.install_paths {
            let absolute = crate::cas_file::safe_join_path(root, install_path)?;
            let metadata = fs::symlink_metadata(&absolute)
                .with_context(|| format!("Failed to inspect {}", absolute.display()))?;
            covered_paths.push(CoveredPath {
                absolute,
                is_dir: metadata.is_dir(),
            });
            install_paths.push(normalize_path_for_pointer(install_path));
        }
        install_paths.sort();
        install_paths.dedup();

        pointer_packages.push(PkgPointerPackage {
            package_key: package.package_key.clone(),
            blob_digest: package_tar.digest,
            install_paths,
            lock_integrity: package.lock_integrity.clone(),
        });
    }

    let mut fixups = scan_residual_layout(root, &covered_paths, &mut blob_by_digest)?;
    fixups.sort_by(fixup_sort_key);
    let blobs = blob_by_digest.into_values().collect::<Vec<_>>();
    let total_blob_bytes = blobs.iter().map(|blob| blob.size_bytes).sum();

    Ok(PkgLayoutScan {
        ecosystem: ecosystem.to_string(),
        compatibility,
        packages: pointer_packages,
        fixups,
        blobs,
        total_blob_bytes,
        temp_dir,
    })
}

pub async fn materialize_pkg_cas_entries(
    root: &Path,
    pointer: &PkgPointer,
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<()> {
    let root = root.to_path_buf();
    let pointer = pointer.clone();
    let blob_path_by_digest = blob_path_by_digest.clone();
    if packages_can_materialize_concurrently(&pointer.packages) {
        materialize_pkg_cas_entries_parallel(
            &root,
            &pointer,
            &blob_path_by_digest,
            allow_external_symlinks,
        )
        .await
    } else {
        tokio::task::spawn_blocking(move || {
            materialize_pkg_cas_entries_blocking(
                &root,
                &pointer,
                &blob_path_by_digest,
                allow_external_symlinks,
            )
        })
        .await
        .context("Package CAS materialization task panicked")?
    }
}

async fn materialize_pkg_cas_entries_parallel(
    root: &Path,
    pointer: &PkgPointer,
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<()> {
    tokio::fs::create_dir_all(root)
        .await
        .with_context(|| format!("Failed to create {}", root.display()))?;

    let mut jobs =
        package_extract_jobs(root, pointer, blob_path_by_digest, allow_external_symlinks)?;
    jobs.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| left.package_key.cmp(&right.package_key))
    });

    let max_concurrent = crate::command_support::get_optimal_concurrency(jobs.len(), "restore");
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1)));
    let mut tasks = JoinSet::new();

    for job in jobs {
        let semaphore = semaphore.clone();
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow!("Package materialize semaphore closed: {error}"))?;
            tokio::task::spawn_blocking(move || extract_package_job(job))
                .await
                .context("Package extract task panicked")?
        });
    }

    while let Some(task_result) = tasks.join_next().await {
        task_result.context("Package materialize task panicked")??;
    }

    let root = root.to_path_buf();
    let pointer = pointer.clone();
    let blob_path_by_digest = blob_path_by_digest.clone();
    tokio::task::spawn_blocking(move || {
        apply_fixups_and_verify(
            &root,
            &pointer,
            &blob_path_by_digest,
            allow_external_symlinks,
        )
    })
    .await
    .context("Package CAS materialization task panicked")?
}

pub fn normalize_path_for_pointer(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn digest_file(path: &Path) -> Result<String> {
    tar::hash_file(path)
}

fn scan_residual_layout(
    root: &Path,
    covered_paths: &[CoveredPath],
    blob_by_digest: &mut BTreeMap<String, PkgBlobSource>,
) -> Result<Vec<PkgFixup>> {
    let mut entries = BTreeMap::new();
    if root.exists() {
        let mut children = fs::read_dir(root)
            .with_context(|| format!("Failed to read directory {}", root.display()))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("Failed to read directory {}", root.display()))?;
        children.sort_by(|left, right| {
            normalize_path_for_pointer(left).cmp(&normalize_path_for_pointer(right))
        });
        for child in children {
            tar::collect_tree(root, &child, &mut entries)?;
        }
    }

    let mut fixups = Vec::new();
    for (relative, absolute) in entries {
        if relative.is_empty() || is_covered(&absolute, covered_paths) {
            continue;
        }

        let metadata = fs::symlink_metadata(&absolute)
            .with_context(|| format!("Failed to inspect {}", absolute.display()))?;
        if metadata.is_dir() {
            fixups.push(PkgFixup::Dir { rel: relative });
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&absolute)
                .with_context(|| format!("Failed to read symlink {}", absolute.display()))?;
            fixups.push(PkgFixup::Symlink {
                link_rel: relative,
                target: target.to_string_lossy().into_owned(),
            });
        } else if metadata.is_file() {
            let digest = tar::hash_file(&absolute)?;
            blob_by_digest
                .entry(digest.clone())
                .or_insert_with(|| PkgBlobSource {
                    digest: digest.clone(),
                    size_bytes: metadata.len(),
                    path: absolute.clone(),
                });
            fixups.push(PkgFixup::StateFile {
                rel: relative,
                blob_digest: digest,
            });
        }
    }

    Ok(fixups)
}

fn is_covered(absolute: &Path, covered_paths: &[CoveredPath]) -> bool {
    covered_paths.iter().any(|covered| {
        absolute == covered.absolute || (covered.is_dir && absolute.starts_with(&covered.absolute))
    })
}

fn fixup_sort_key(left: &PkgFixup, right: &PkgFixup) -> std::cmp::Ordering {
    fixup_rel(left)
        .cmp(fixup_rel(right))
        .then_with(|| fixup_rank(left).cmp(&fixup_rank(right)))
}

fn fixup_rel(fixup: &PkgFixup) -> &str {
    match fixup {
        PkgFixup::Dir { rel } => rel,
        PkgFixup::Symlink { link_rel, .. } => link_rel,
        PkgFixup::StateFile { rel, .. } => rel,
    }
}

fn fixup_rank(fixup: &PkgFixup) -> u8 {
    match fixup {
        PkgFixup::Dir { .. } => 0,
        PkgFixup::StateFile { .. } => 1,
        PkgFixup::Symlink { .. } => 2,
    }
}

fn materialize_pkg_cas_entries_blocking(
    root: &Path,
    pointer: &PkgPointer,
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<()> {
    fs::create_dir_all(root).with_context(|| format!("Failed to create {}", root.display()))?;

    for package in &pointer.packages {
        let blob_path = blob_path_by_digest
            .get(&package.blob_digest)
            .ok_or_else(|| anyhow!("Missing package blob {}", package.blob_digest))?;
        extract_package_tar_zstd(root, blob_path, allow_external_symlinks)
            .with_context(|| format!("Failed to extract package {}", package.package_key))?;
    }

    apply_fixups_and_verify(root, pointer, blob_path_by_digest, allow_external_symlinks)
}

fn apply_fixups_and_verify(
    root: &Path,
    pointer: &PkgPointer,
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<()> {
    for fixup in pointer.fixups.iter().filter(|fixup| fixup_rank(fixup) == 0) {
        apply_fixup(root, fixup, blob_path_by_digest, allow_external_symlinks)?;
    }
    for fixup in pointer.fixups.iter().filter(|fixup| fixup_rank(fixup) == 1) {
        apply_fixup(root, fixup, blob_path_by_digest, allow_external_symlinks)?;
    }
    for fixup in pointer.fixups.iter().filter(|fixup| fixup_rank(fixup) == 2) {
        apply_fixup(root, fixup, blob_path_by_digest, allow_external_symlinks)?;
    }

    verify_install_paths(root, pointer)
}

#[derive(Debug)]
struct PackageExtractJob {
    root: PathBuf,
    package_key: String,
    blob_path: PathBuf,
    size_bytes: u64,
    allow_external_symlinks: bool,
}

fn package_extract_jobs(
    root: &Path,
    pointer: &PkgPointer,
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<Vec<PackageExtractJob>> {
    let blob_sizes = pointer
        .blobs
        .iter()
        .map(|blob| (blob.digest.as_str(), blob.size_bytes))
        .collect::<HashMap<_, _>>();
    let mut jobs = Vec::with_capacity(pointer.packages.len());

    for package in &pointer.packages {
        let blob_path = blob_path_by_digest
            .get(&package.blob_digest)
            .ok_or_else(|| anyhow!("Missing package blob {}", package.blob_digest))?;
        jobs.push(PackageExtractJob {
            root: root.to_path_buf(),
            package_key: package.package_key.clone(),
            blob_path: blob_path.clone(),
            size_bytes: *blob_sizes.get(package.blob_digest.as_str()).unwrap_or(&0),
            allow_external_symlinks,
        });
    }

    Ok(jobs)
}

fn extract_package_job(job: PackageExtractJob) -> Result<()> {
    extract_package_tar_zstd(&job.root, &job.blob_path, job.allow_external_symlinks)
        .with_context(|| format!("Failed to extract package {}", job.package_key))
}

fn packages_can_materialize_concurrently(packages: &[PkgPointerPackage]) -> bool {
    #[derive(Debug)]
    struct InstallPath<'a> {
        package_index: usize,
        path: &'a str,
    }

    let mut install_paths = Vec::new();
    for (package_index, package) in packages.iter().enumerate() {
        for install_path in &package.install_paths {
            install_paths.push(InstallPath {
                package_index,
                path: install_path.trim_end_matches('/'),
            });
        }
    }
    install_paths.sort_by(|left, right| left.path.cmp(right.path));

    let mut ancestors: Vec<InstallPath<'_>> = Vec::new();
    for install_path in install_paths {
        while ancestors
            .last()
            .is_some_and(|ancestor| !path_contains(ancestor.path, install_path.path))
        {
            ancestors.pop();
        }
        if ancestors.iter().any(|ancestor| {
            ancestor.package_index != install_path.package_index
                && path_contains(ancestor.path, install_path.path)
        }) {
            return false;
        }
        ancestors.push(install_path);
    }

    true
}

fn path_contains(parent: &str, child: &str) -> bool {
    parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn extract_package_tar_zstd(
    root: &Path,
    blob_path: &Path,
    allow_external_symlinks: bool,
) -> Result<()> {
    let file = fs::File::open(blob_path)
        .with_context(|| format!("Failed to open {}", blob_path.display()))?;
    let reader = BufReader::new(file);
    let decoder = ZstdDecoder::new(reader)
        .with_context(|| format!("Failed to decode package blob {}", blob_path.display()))?;
    let mut archive = ::tar::Archive::new(decoder);

    for entry in archive.entries().context("Failed to read package tar")? {
        let mut entry = entry.context("Failed to read package tar entry")?;
        let relative = entry
            .path()
            .context("Failed to read package tar path")?
            .into_owned();
        let destination = crate::cas_file::safe_join_path(root, &relative)?;
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            create_dir_all_without_symlink(root, &destination)?;
            continue;
        }

        ensure_parent_directory(root, &destination)?;

        if entry_type.is_symlink() {
            let target = entry
                .link_name()
                .context("Failed to read package symlink target")?
                .ok_or_else(|| anyhow!("Package symlink {} missing target", relative.display()))?;
            crate::cas_file::validate_symlink_target(
                root,
                &destination,
                &target,
                allow_external_symlinks,
            )?;
            remove_path_if_exists_blocking(&destination)?;
            create_symlink_blocking(&destination, &target)?;
            continue;
        }

        if entry_type.is_file() {
            remove_path_if_exists_blocking(&destination)?;
            entry
                .unpack(&destination)
                .with_context(|| format!("Failed to unpack {}", destination.display()))?;
            normalize_restored_file_mode(&destination, entry.header().mode().unwrap_or(0o644))?;
            continue;
        }

        return Err(anyhow!(
            "Unsupported package tar entry {}",
            relative.display()
        ));
    }

    Ok(())
}

fn apply_fixup(
    root: &Path,
    fixup: &PkgFixup,
    blob_path_by_digest: &HashMap<String, PathBuf>,
    allow_external_symlinks: bool,
) -> Result<()> {
    match fixup {
        PkgFixup::Dir { rel } => {
            let destination = crate::cas_file::safe_join(root, rel)?;
            create_dir_all_without_symlink(root, &destination)?;
        }
        PkgFixup::StateFile { rel, blob_digest } => {
            let destination = crate::cas_file::safe_join(root, rel)?;
            ensure_parent_directory(root, &destination)?;
            let blob_path = blob_path_by_digest
                .get(blob_digest)
                .ok_or_else(|| anyhow!("Missing state-file blob {}", blob_digest))?;
            remove_path_if_exists_blocking(&destination)?;
            fs::copy(blob_path, &destination).with_context(|| {
                format!(
                    "Failed to restore package state file {}",
                    destination.display()
                )
            })?;
            normalize_restored_file_mode(&destination, 0o644)?;
        }
        PkgFixup::Symlink { link_rel, target } => {
            let destination = crate::cas_file::safe_join(root, link_rel)?;
            ensure_parent_directory(root, &destination)?;
            let target_path = PathBuf::from(target);
            crate::cas_file::validate_symlink_target(
                root,
                &destination,
                &target_path,
                allow_external_symlinks,
            )?;
            remove_path_if_exists_blocking(&destination)?;
            create_symlink_blocking(&destination, &target_path)?;
        }
    }
    Ok(())
}

fn ensure_parent_directory(root: &Path, destination: &Path) -> Result<()> {
    let parent = destination.parent().ok_or_else(|| {
        anyhow!(
            "Package CAS destination has no parent directory: {}",
            destination.display()
        )
    })?;
    create_dir_all_without_symlink(root, parent)
}

fn create_dir_all_without_symlink(root: &Path, directory: &Path) -> Result<()> {
    let relative = directory.strip_prefix(root).with_context(|| {
        format!(
            "Package CAS destination {} is not under {}",
            directory.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();

    for component in relative.components() {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!(
                    "Package CAS destination contains unsupported path component: {}",
                    directory.display()
                ));
            }
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(anyhow!(
                    "Package CAS refuses to write through symlink directory {}",
                    current.display()
                ));
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(anyhow!(
                    "Package CAS destination parent is not a directory: {}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_one_directory_without_symlink(&current)?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to inspect {}", current.display()));
            }
        }
    }

    Ok(())
}

fn create_one_directory_without_symlink(directory: &Path) -> Result<()> {
    match fs::create_dir(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(directory)
                .with_context(|| format!("Failed to inspect {}", directory.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "Package CAS refuses to write through symlink directory {}",
                    directory.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(anyhow!(
                    "Package CAS destination parent is not a directory: {}",
                    directory.display()
                ));
            }
            Ok(())
        }
        Err(error) => {
            Err(error).with_context(|| format!("Failed to create {}", directory.display()))
        }
    }
}

fn verify_install_paths(root: &Path, pointer: &PkgPointer) -> Result<()> {
    for package in &pointer.packages {
        for install_path in &package.install_paths {
            let destination = crate::cas_file::safe_join(root, install_path)?;
            if !destination.exists() && fs::symlink_metadata(&destination).is_err() {
                return Err(anyhow!(
                    "Package CAS restore did not materialize {} for {}",
                    install_path,
                    package.package_key
                ));
            }
        }
    }
    Ok(())
}

fn remove_path_if_exists_blocking(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                fs::remove_dir_all(path)
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
            } else {
                fs::remove_file(path)
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn create_symlink_blocking(path: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, path)
        .with_context(|| format!("Failed to create symlink {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn create_symlink_blocking(path: &Path, target: &Path) -> Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    if symlink_file(target, path).is_err() {
        symlink_dir(target, path)
            .with_context(|| format!("Failed to create symlink {}", path.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_restored_file_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
        .with_context(|| format!("Failed to set permissions for {}", path.display()))
}

#[cfg(not(unix))]
fn normalize_restored_file_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    #[tokio::test]
    async fn scan_and_materialize_preserves_package_and_residual_state() {
        let source = tempfile::tempdir().unwrap();
        let root = source.path();
        fs::create_dir_all(root.join("ruby/3.4.0/gems/json-2.7.2/lib")).unwrap();
        fs::create_dir_all(root.join("ruby/3.4.0/specifications")).unwrap();
        fs::create_dir_all(root.join("ruby/3.4.0/bin")).unwrap();
        fs::write(
            root.join("ruby/3.4.0/gems/json-2.7.2/lib/json.rb"),
            "module JSON; end\n",
        )
        .unwrap();
        fs::write(
            root.join("ruby/3.4.0/specifications/json-2.7.2.gemspec"),
            "Gem::Specification.new\n",
        )
        .unwrap();
        fs::write(root.join("ruby/3.4.0/bin/json_pp"), "#!/usr/bin/env ruby\n").unwrap();

        let packages = vec![crate::pkg_adapters::ResolvedPackage {
            package_key: "bundler:3.4.0:json-2.7.2".to_string(),
            lock_integrity: None,
            install_paths: vec![
                PathBuf::from("ruby/3.4.0/gems/json-2.7.2"),
                PathBuf::from("ruby/3.4.0/specifications/json-2.7.2.gemspec"),
            ],
            no_integrity: true,
        }];

        let scan = scan_packages(root, "bundler", None, &packages).unwrap();
        assert_eq!(scan.packages.len(), 1);
        assert!(scan.fixups.iter().any(|fixup| {
            matches!(
                fixup,
                PkgFixup::StateFile { rel, .. } if rel == "ruby/3.4.0/bin/json_pp"
            )
        }));

        let pointer_bytes = build_pointer(&scan).unwrap();
        let pointer = parse_pointer(&pointer_bytes).unwrap();
        let blob_path_by_digest = scan
            .blobs
            .iter()
            .map(|blob| (blob.digest.clone(), blob.path.clone()))
            .collect::<HashMap<_, _>>();
        let target = tempfile::tempdir().unwrap();
        materialize_pkg_cas_entries(target.path(), &pointer, &blob_path_by_digest, false)
            .await
            .unwrap();

        assert!(
            target
                .path()
                .join("ruby/3.4.0/gems/json-2.7.2/lib/json.rb")
                .is_file()
        );
        assert!(
            target
                .path()
                .join("ruby/3.4.0/specifications/json-2.7.2.gemspec")
                .is_file()
        );
        assert!(target.path().join("ruby/3.4.0/bin/json_pp").is_file());
    }

    #[test]
    fn package_blobs_are_zstd_tars() {
        let source = tempfile::tempdir().unwrap();
        let root = source.path();
        fs::create_dir_all(root.join("ruby/3.4.0/gems/big-1.0.0/lib")).unwrap();
        fs::write(
            root.join("ruby/3.4.0/gems/big-1.0.0/lib/big.rb"),
            "module Big\n".repeat(128),
        )
        .unwrap();

        let packages = vec![crate::pkg_adapters::ResolvedPackage {
            package_key: "bundler:3.4.0:big-1.0.0".to_string(),
            lock_integrity: None,
            install_paths: vec![PathBuf::from("ruby/3.4.0/gems/big-1.0.0")],
            no_integrity: true,
        }];

        let scan = scan_packages(root, "bundler", None, &packages).unwrap();
        let blob = &scan.blobs[0];
        let bytes = fs::read(&blob.path).unwrap();

        assert_eq!(&bytes[..4], &[0x28, 0xb5, 0x2f, 0xfd]);

        let decoded = zstd::stream::decode_all(bytes.as_slice()).unwrap();
        let mut archive = ::tar::Archive::new(decoded.as_slice());
        let paths = archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert!(
            paths
                .iter()
                .any(|path| path == "ruby/3.4.0/gems/big-1.0.0/lib/big.rb")
        );

        let pointer = parse_pointer(&build_pointer(&scan).unwrap()).unwrap();
        assert_eq!(pointer.format_version, FORMAT_VERSION);
    }

    #[test]
    fn package_tar_digest_is_stable_for_same_content() {
        let source = tempfile::tempdir().unwrap();
        let root = source.path();
        fs::create_dir_all(root.join("ruby/3.4.0/gems/rake-13.2.1/lib")).unwrap();
        fs::write(
            root.join("ruby/3.4.0/gems/rake-13.2.1/lib/rake.rb"),
            "module Rake; end\n",
        )
        .unwrap();

        let packages = vec![crate::pkg_adapters::ResolvedPackage {
            package_key: "bundler:3.4.0:rake-13.2.1".to_string(),
            lock_integrity: None,
            install_paths: vec![PathBuf::from("ruby/3.4.0/gems/rake-13.2.1")],
            no_integrity: true,
        }];

        let first = scan_packages(root, "bundler", None, &packages).unwrap();
        let second = scan_packages(root, "bundler", None, &packages).unwrap();

        assert_eq!(
            first.packages[0].blob_digest,
            second.packages[0].blob_digest
        );
    }

    #[test]
    fn parallel_materialization_is_allowed_for_disjoint_package_paths() {
        let packages = vec![
            PkgPointerPackage {
                package_key: "bundler:3.4.0:json-2.7.2".to_string(),
                blob_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                install_paths: vec![
                    "ruby/3.4.0/gems/json-2.7.2".to_string(),
                    "ruby/3.4.0/specifications/json-2.7.2.gemspec".to_string(),
                ],
                lock_integrity: None,
            },
            PkgPointerPackage {
                package_key: "bundler:3.4.0:rake-13.2.1".to_string(),
                blob_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                install_paths: vec![
                    "ruby/3.4.0/gems/rake-13.2.1".to_string(),
                    "ruby/3.4.0/specifications/rake-13.2.1.gemspec".to_string(),
                ],
                lock_integrity: None,
            },
        ];

        assert!(packages_can_materialize_concurrently(&packages));
    }

    #[test]
    fn parallel_materialization_is_disabled_for_nested_package_paths() {
        let packages = vec![
            PkgPointerPackage {
                package_key: "npm:parent@1.0.0:node_modules/parent".to_string(),
                blob_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                install_paths: vec!["parent".to_string()],
                lock_integrity: None,
            },
            PkgPointerPackage {
                package_key: "npm:child@1.0.0:node_modules/parent/node_modules/child".to_string(),
                blob_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                install_paths: vec!["parent/node_modules/child".to_string()],
                lock_integrity: None,
            },
        ];

        assert!(!packages_can_materialize_concurrently(&packages));
    }

    #[test]
    fn pointer_rejects_path_traversal() {
        let pointer = serde_json::json!({
            "format_version": FORMAT_VERSION,
            "adapter": ADAPTER,
            "ecosystem": "bundler",
            "packages": [{
                "package_key": "bundler:3.4.0:bad-1.0.0",
                "blob_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "install_paths": ["../bad"]
            }],
            "fixups": [],
            "blobs": [{
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size_bytes": 1
            }]
        });

        let error = parse_pointer(&serde_json::to_vec(&pointer).unwrap()).unwrap_err();
        assert!(error.to_string().contains("Invalid package install path"));
    }

    #[test]
    fn pointer_rejects_old_uncompressed_package_format() {
        let pointer = serde_json::json!({
            "format_version": 1,
            "adapter": ADAPTER,
            "ecosystem": "bundler",
            "packages": [{
                "package_key": "bundler:3.4.0:old-1.0.0",
                "blob_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "install_paths": ["ruby/3.4.0/gems/old-1.0.0"]
            }],
            "fixups": [],
            "blobs": [{
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size_bytes": 1
            }]
        });

        let error = parse_pointer(&serde_json::to_vec(&pointer).unwrap()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Unsupported package CAS pointer version 1")
        );
    }

    #[tokio::test]
    async fn materialize_rejects_package_tar_path_traversal() {
        let source = tempfile::tempdir().unwrap();
        let blob_path = source.path().join("bad.tar.zst");
        let digest = write_test_package_blob_from_tar_bytes(
            &blob_path,
            raw_tar_with_file("../escaped.txt", b"oops"),
        );
        let size_bytes = fs::metadata(&blob_path).unwrap().len();
        let pointer = test_pointer(digest.clone(), size_bytes, vec!["safe".to_string()]);
        let mut blobs = HashMap::new();
        blobs.insert(digest, blob_path);
        let restore_parent = tempfile::tempdir().unwrap();
        let target_path = restore_parent.path().join("restore");
        fs::create_dir(&target_path).unwrap();

        let error = materialize_pkg_cas_entries(&target_path, &pointer, &blobs, false)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Failed to extract package test-package")
        );
        assert!(!target_path.join("escaped.txt").exists());
        assert!(!restore_parent.path().join("escaped.txt").exists());
    }

    #[tokio::test]
    async fn materialize_refuses_to_write_through_symlink_parent() {
        let source = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let blob_path = source.path().join("symlink-parent.tar.zst");
        let outside_target = outside.path().join("outside");
        fs::create_dir_all(&outside_target).unwrap();
        let digest = write_test_package_blob(&blob_path, |builder| {
            append_test_dir(builder, "pkg");
            append_test_symlink(builder, "pkg/link", &outside_target);
            append_test_file(builder, "pkg/link/pwned.txt", b"nope");
        });
        let size_bytes = fs::metadata(&blob_path).unwrap().len();
        let pointer = test_pointer(digest.clone(), size_bytes, vec!["pkg".to_string()]);
        let mut blobs = HashMap::new();
        blobs.insert(digest, blob_path);
        let target = tempfile::tempdir().unwrap();

        let error = materialize_pkg_cas_entries(target.path(), &pointer, &blobs, true)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Failed to extract package test-package")
        );
        assert!(!outside_target.join("pwned.txt").exists());
    }

    fn test_pointer(digest: String, size_bytes: u64, install_paths: Vec<String>) -> PkgPointer {
        PkgPointer {
            format_version: FORMAT_VERSION,
            adapter: ADAPTER.to_string(),
            ecosystem: "test".to_string(),
            install_root_rel: None,
            compatibility: None,
            packages: vec![PkgPointerPackage {
                package_key: "test-package".to_string(),
                blob_digest: digest.clone(),
                install_paths,
                lock_integrity: None,
            }],
            fixups: Vec::new(),
            blobs: vec![PkgPointerBlob {
                digest,
                size_bytes,
                sequence: Some(0),
            }],
        }
    }

    fn write_test_package_blob(
        blob_path: &Path,
        write_entries: impl FnOnce(&mut ::tar::Builder<Vec<u8>>),
    ) -> String {
        let mut builder = ::tar::Builder::new(Vec::new());
        builder.mode(::tar::HeaderMode::Deterministic);
        write_entries(&mut builder);
        let tar_bytes = builder.into_inner().unwrap();
        let compressed = zstd::stream::encode_all(tar_bytes.as_slice(), 3).unwrap();
        fs::write(blob_path, compressed).unwrap();
        tar::hash_file(blob_path).unwrap()
    }

    fn write_test_package_blob_from_tar_bytes(blob_path: &Path, tar_bytes: Vec<u8>) -> String {
        let compressed = zstd::stream::encode_all(tar_bytes.as_slice(), 3).unwrap();
        fs::write(blob_path, compressed).unwrap();
        tar::hash_file(blob_path).unwrap()
    }

    fn append_test_dir(builder: &mut ::tar::Builder<Vec<u8>>, path: &str) {
        let mut header = test_header(::tar::EntryType::Directory, 0, 0o755);
        builder
            .append_data(&mut header, path, std::io::empty())
            .unwrap();
    }

    fn append_test_file(builder: &mut ::tar::Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
        let mut header = test_header(::tar::EntryType::Regular, bytes.len() as u64, 0o644);
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    fn append_test_symlink(builder: &mut ::tar::Builder<Vec<u8>>, path: &str, target: &Path) {
        let mut header = test_header(::tar::EntryType::Symlink, 0, 0o755);
        builder.append_link(&mut header, path, target).unwrap();
    }

    fn test_header(entry_type: ::tar::EntryType, size: u64, mode: u32) -> ::tar::Header {
        let mut header = ::tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(size);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_username("").unwrap();
        header.set_groupname("").unwrap();
        header.set_cksum();
        header
    }

    fn raw_tar_with_file(path: &str, bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let mut header = [0u8; 512];
        write_tar_string(&mut header[0..100], path);
        write_tar_octal(&mut header[100..108], 0o644);
        write_tar_octal(&mut header[108..116], 0);
        write_tar_octal(&mut header[116..124], 0);
        write_tar_octal(&mut header[124..136], bytes.len() as u64);
        write_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        write_tar_string(&mut header[257..263], "ustar");
        write_tar_string(&mut header[263..265], "00");

        let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());

        output.extend_from_slice(&header);
        output.extend_from_slice(bytes);
        let padding = (512 - (bytes.len() % 512)) % 512;
        output.extend(std::iter::repeat_n(0, padding));
        output.extend_from_slice(&[0u8; 1024]);
        output
    }

    fn write_tar_string(field: &mut [u8], value: &str) {
        let bytes = value.as_bytes();
        let len = bytes.len().min(field.len());
        field[..len].copy_from_slice(&bytes[..len]);
    }

    fn write_tar_octal(field: &mut [u8], value: u64) {
        let text = format!("{value:0width$o}\0", width = field.len() - 1);
        field.copy_from_slice(text.as_bytes());
    }
}

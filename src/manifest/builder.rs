use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use walkdir::WalkDir;

use super::model::EntryType;

#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub path: String,
    pub entry_type: EntryType,
    pub size: u64,
    pub mode: u32,
    pub target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ManifestDraft {
    pub descriptors: Vec<FileDescriptor>,
    pub raw_size: u64,
    pub entry_count: u64,
}

pub struct ManifestBuilder<'a> {
    root: &'a Path,
}

impl<'a> ManifestBuilder<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub fn build(&self) -> Result<ManifestDraft> {
        let mut descriptors = Vec::new();
        let mut raw_size = 0u64;

        // Handle single file case
        let root_metadata = fs::symlink_metadata(self.root)
            .with_context(|| format!("Failed to inspect {}", self.root.display()))?;

        if root_metadata.is_file() {
            // Root is a single file, not a directory
            let size = root_metadata.len();
            let mode = file_mode(&root_metadata, EntryType::File);

            // Use filename as the relative path
            let filename = self
                .root
                .file_name()
                .context("Failed to get filename from path")?
                .to_string_lossy()
                .to_string();

            descriptors.push(FileDescriptor {
                path: filename,
                entry_type: EntryType::File,
                size,
                mode,
                target: None,
            });

            return Ok(ManifestDraft {
                descriptors,
                raw_size: size,
                entry_count: 1,
            });
        }

        // Root is a directory, walk it
        for entry in WalkDir::new(self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|dir_entry| {
                if dir_entry.depth() == 0 {
                    return true;
                }

                let rel = match dir_entry.path().strip_prefix(self.root) {
                    Ok(path) => path,
                    Err(_) => return false,
                };

                let rel_str = normalize_manifest_path(rel);
                !should_skip_for_manifest(&rel_str)
            })
        {
            let dir_entry = entry.context("Failed to walk directory while building manifest")?;
            if dir_entry.depth() == 0 {
                continue;
            }

            let absolute_path = dir_entry.path();
            let relative = absolute_path
                .strip_prefix(self.root)
                .context("Failed to compute relative path for manifest entry")?;

            if relative.as_os_str().is_empty() {
                continue;
            }

            let relative_path = normalize_manifest_path(relative);
            if should_skip_for_manifest(&relative_path) {
                continue;
            }

            let metadata = fs::symlink_metadata(absolute_path).with_context(|| {
                format!("Failed to inspect metadata for {}", absolute_path.display())
            })?;

            let entry_type = if metadata.file_type().is_dir() {
                EntryType::Dir
            } else if metadata.file_type().is_symlink() {
                EntryType::Symlink
            } else {
                EntryType::File
            };

            let size = if entry_type == EntryType::File {
                metadata.len()
            } else {
                0
            };

            let mode = file_mode(&metadata, entry_type);
            let target = if entry_type == EntryType::Symlink {
                let link_target = fs::read_link(absolute_path).with_context(|| {
                    format!(
                        "Failed to read symlink target for {}",
                        absolute_path.display()
                    )
                })?;
                Some(link_target.to_string_lossy().to_string())
            } else {
                None
            };

            if entry_type == EntryType::File {
                raw_size = raw_size.saturating_add(size);
            }

            descriptors.push(FileDescriptor {
                path: relative_path,
                entry_type,
                size,
                mode,
                target,
            });
        }

        descriptors.sort_by(|a, b| a.path.cmp(&b.path));

        let entry_count = descriptors.len() as u64;

        Ok(ManifestDraft {
            descriptors,
            raw_size,
            entry_count,
        })
    }
}

fn normalize_manifest_path(path: &Path) -> String {
    let mut normalized = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");

    if cfg!(windows) {
        normalized = normalized.replace('\\', "/");
    }

    normalized.trim_start_matches("./").to_string()
}

fn should_skip_for_manifest(path: &str) -> bool {
    const SKIP_PATTERNS: &[&str] = &[
        ".git/",
        ".svn/",
        ".hg/",
        ".bzr/",
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        "*.tmp",
        "*.temp",
        "~*",
        ".#*",
        "*.log",
        "npm-debug.log*",
        "yarn-debug.log*",
        "yarn-error.log*",
        ".cache/",
        "tmp/",
        "temp/",
    ];

    for pattern in SKIP_PATTERNS {
        if pattern.ends_with('/') {
            if path.starts_with(pattern) || path.contains(&format!("/{pattern}")) {
                return true;
            }
        } else if pattern.contains('*') {
            let needle = pattern.replace('*', "");
            if path.ends_with(&needle) {
                return true;
            }
        } else if path.ends_with(pattern) || path == *pattern {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata, _entry_type: EntryType) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn file_mode(metadata: &std::fs::Metadata, entry_type: EntryType) -> u32 {
    const FILE_DEFAULT: u32 = 0o100644;
    const EXECUTABLE_DEFAULT: u32 = 0o100755;
    const DIR_DEFAULT: u32 = 0o040755;

    if entry_type == EntryType::Dir {
        DIR_DEFAULT
    } else if metadata.permissions().readonly() {
        FILE_DEFAULT
    } else {
        EXECUTABLE_DEFAULT
    }
}

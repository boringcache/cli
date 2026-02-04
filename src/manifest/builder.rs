use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use jwalk::WalkDir;
use rayon::prelude::*;

use super::model::EntryType;

#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub path: String,
    pub entry_type: EntryType,
    pub size: u64,
    pub executable: Option<bool>,
    pub target: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ManifestDraft {
    pub descriptors: Vec<FileDescriptor>,
    pub raw_size: u64,
    pub entry_count: u64,
}

pub struct ManifestBuilder<'a> {
    root: &'a Path,
    exclude_patterns: Vec<String>,
}

impl<'a> ManifestBuilder<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self {
            root,
            exclude_patterns: Vec::new(),
        }
    }

    pub fn with_exclude_patterns(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    pub fn build(&self) -> Result<ManifestDraft> {
        let root_metadata = fs::symlink_metadata(self.root)
            .with_context(|| format!("Failed to inspect {}", self.root.display()))?;

        if root_metadata.is_file() {
            let size = root_metadata.len();
            let executable = Some(is_executable(&root_metadata));
            let hash = Some(calculate_file_hash(self.root)?);

            let filename = self
                .root
                .file_name()
                .context("Failed to get filename from path")?
                .to_string_lossy()
                .to_string();

            return Ok(ManifestDraft {
                descriptors: vec![FileDescriptor {
                    path: filename,
                    entry_type: EntryType::File,
                    size,
                    executable,
                    target: None,
                    hash,
                }],
                raw_size: size,
                entry_count: 1,
            });
        }

        let root = self.root;
        let exclude_patterns = self.exclude_patterns.clone();
        let root_for_filter = root.to_path_buf();
        let paths: Vec<PathBuf> = WalkDir::new(root)
            .follow_links(false)
            .skip_hidden(false)
            .process_read_dir(move |_depth, _path, _read_dir_state, children| {
                children.retain(|entry| {
                    if let Ok(ref dir_entry) = entry {
                        let path = dir_entry.path();
                        if let Ok(rel) = path.strip_prefix(&root_for_filter) {
                            let rel_str = normalize_manifest_path(rel);
                            return !should_skip_for_manifest(&rel_str)
                                && !matches_exclude_pattern(&rel_str, &exclude_patterns);
                        }
                    }
                    true
                });
            })
            .into_iter()
            .filter_map(|entry| {
                let dir_entry = entry.ok()?;
                if dir_entry.depth == 0 {
                    return None;
                }

                let absolute_path = dir_entry.path();
                let relative = absolute_path.strip_prefix(root).ok()?;

                if relative.as_os_str().is_empty() {
                    return None;
                }

                let relative_path = normalize_manifest_path(relative);
                if should_skip_for_manifest(&relative_path) {
                    return None;
                }
                if matches_exclude_pattern(&relative_path, &self.exclude_patterns) {
                    return None;
                }

                Some(absolute_path)
            })
            .collect();

        let raw_size = AtomicU64::new(0);

        let descriptors: Result<Vec<FileDescriptor>> = paths
            .par_iter()
            .map(|absolute_path| {
                let relative = absolute_path
                    .strip_prefix(root)
                    .context("Failed to compute relative path for manifest entry")?;

                let relative_path = normalize_manifest_path(relative);

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
                    let len = metadata.len();
                    raw_size.fetch_add(len, Ordering::Relaxed);
                    len
                } else {
                    0
                };

                let executable = if entry_type == EntryType::File {
                    Some(is_executable(&metadata))
                } else {
                    None
                };

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

                let hash = if entry_type == EntryType::File {
                    Some(calculate_file_hash(absolute_path)?)
                } else {
                    None
                };

                Ok(FileDescriptor {
                    path: relative_path,
                    entry_type,
                    size,
                    executable,
                    target,
                    hash,
                })
            })
            .collect();

        let mut descriptors = descriptors?;
        descriptors.sort_by(|a, b| a.path.cmp(&b.path));

        let entry_count = descriptors.len() as u64;
        let raw_size = raw_size.load(Ordering::Relaxed);

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

const BUILTIN_SKIP_PATTERNS: &[&str] = &[
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
    "npm-debug.log*",
    "yarn-debug.log*",
    "yarn-error.log*",
];

fn should_skip_for_manifest(path: &str) -> bool {
    matches_any_pattern(path, BUILTIN_SKIP_PATTERNS)
}

fn matches_exclude_pattern(path: &str, patterns: &[String]) -> bool {
    let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.trim()).collect();
    matches_any_pattern(path, &pattern_refs)
}

fn matches_any_pattern(path: &str, patterns: &[&str]) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);

    for pattern in patterns {
        if pattern.is_empty() {
            continue;
        }

        if pattern.ends_with('/') {
            if path.starts_with(pattern) || path.contains(&format!("/{pattern}")) {
                return true;
            }
            continue;
        }

        let target = if pattern.contains('/') {
            path
        } else {
            filename
        };

        if matches_glob(target, pattern) {
            return true;
        }
    }
    false
}

fn matches_glob(text: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return text == pattern;
    }

    if let Some(middle) = pattern.strip_prefix('*').and_then(|p| p.strip_suffix('*')) {
        if !middle.is_empty() {
            return text.contains(middle);
        }
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }

    if let Some(star_pos) = pattern.find('*') {
        let (prefix, suffix) = (&pattern[..star_pos], &pattern[star_pos + 1..]);
        return text.starts_with(prefix)
            && text.ends_with(suffix)
            && text.len() >= pattern.len() - 1;
    }

    false
}

fn calculate_file_hash(path: &Path) -> Result<String> {
    use std::io::{BufReader, Read};

    const BUFFER_SIZE: usize = 1024 * 1024;

    let file = fs::File::open(path)
        .with_context(|| format!("Failed to open {} for hashing", path.display()))?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (metadata.mode() & 0o111) != 0
}

#[cfg(not(unix))]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    !metadata.permissions().readonly()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_glob_exact() {
        assert!(matches_glob("foo.txt", "foo.txt"));
        assert!(!matches_glob("foo.txt", "bar.txt"));
    }

    #[test]
    fn test_matches_glob_prefix_wildcard() {
        assert!(matches_glob("file.out", "*.out"));
        assert!(matches_glob("gem_make.out", "*.out"));
        assert!(!matches_glob("file.log", "*.out"));
    }

    #[test]
    fn test_matches_glob_suffix_wildcard() {
        assert!(matches_glob("gem_make.out", "gem_*"));
        assert!(matches_glob("gem_foo", "gem_*"));
        assert!(!matches_glob("make.out", "gem_*"));
    }

    #[test]
    fn test_matches_glob_middle_wildcard() {
        assert!(matches_glob("gem_make.out", "gem*.out"));
        assert!(matches_glob("gem.out", "gem*.out"));
        assert!(!matches_glob("foo.out", "gem*.out"));
    }

    #[test]
    fn test_matches_glob_contains() {
        assert!(matches_glob("test_make_file", "*make*"));
        assert!(matches_glob("make", "*make*"));
        assert!(!matches_glob("test", "*make*"));
    }

    #[test]
    fn test_matches_exclude_pattern_filename() {
        let patterns = vec!["*.out".to_string(), "*.log".to_string()];
        assert!(matches_exclude_pattern("ruby/gems/gem_make.out", &patterns));
        assert!(matches_exclude_pattern("debug.log", &patterns));
        assert!(!matches_exclude_pattern("main.rs", &patterns));
    }

    #[test]
    fn test_matches_exclude_pattern_with_path() {
        let patterns = vec!["ruby/*.out".to_string()];
        assert!(matches_exclude_pattern("ruby/gem_make.out", &patterns));
        assert!(!matches_exclude_pattern("python/gem_make.out", &patterns));
    }

    #[test]
    fn test_matches_exclude_pattern_empty() {
        let patterns: Vec<String> = vec![];
        assert!(!matches_exclude_pattern("any_file.txt", &patterns));
    }

    #[test]
    fn test_should_skip_builtin_patterns() {
        assert!(should_skip_for_manifest(".git/config"));
        assert!(should_skip_for_manifest("foo/.git/config"));
        assert!(should_skip_for_manifest(".DS_Store"));
        assert!(should_skip_for_manifest("foo/.DS_Store"));
        assert!(should_skip_for_manifest("file.tmp"));
        assert!(!should_skip_for_manifest("src/main.rs"));
    }
}

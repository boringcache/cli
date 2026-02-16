use std::collections::BTreeMap;

use super::builder::{FileDescriptor, ManifestDraft};
use super::model::{EntryState, Manifest, ManifestEntry, ManifestRoot, ManifestSummary};
use anyhow::Result;
use sha2::{Digest, Sha256};

const SHA256_PREFIX: &str = "sha256:";

pub struct ManifestDiffer<'a> {
    tag: &'a str,
}

#[derive(Debug)]
pub struct DiffOutcome {
    pub manifest: Manifest,
    pub changed_paths: Vec<String>,
    pub new_paths: Vec<String>,
    pub removed_paths: Vec<String>,
    pub unchanged_paths: Vec<String>,
}

impl<'a> ManifestDiffer<'a> {
    pub fn new(tag: &'a str) -> Self {
        Self { tag }
    }

    pub fn diff(&self, draft: ManifestDraft, previous: Option<&Manifest>) -> Result<DiffOutcome> {
        let mut previous_map: BTreeMap<String, ManifestEntry> = BTreeMap::new();
        if let Some(previous_manifest) = previous {
            for entry in &previous_manifest.files {
                if entry.state == EntryState::Present {
                    previous_map.insert(entry.path.clone(), entry.clone());
                }
            }
        }

        let mut entries: Vec<ManifestEntry> =
            Vec::with_capacity(draft.descriptors.len() + previous_map.len());
        let mut changed_paths = Vec::new();
        let mut new_paths = Vec::new();
        let mut removed_paths = Vec::new();
        let mut unchanged_paths = Vec::new();

        for descriptor in draft.descriptors {
            if let Some(previous_entry) = previous_map.remove(&descriptor.path) {
                if metadata_equal(&descriptor, &previous_entry) {
                    unchanged_paths.push(descriptor.path.clone());
                } else {
                    changed_paths.push(descriptor.path.clone());
                }
            } else {
                new_paths.push(descriptor.path.clone());
            }

            entries.push(ManifestEntry {
                path: descriptor.path,
                entry_type: descriptor.entry_type,
                size: descriptor.size,
                executable: descriptor.executable,
                hash: descriptor.hash,
                target: descriptor.target,
                state: EntryState::Present,
            });
        }

        for (_path, previous_entry) in previous_map.into_iter() {
            removed_paths.push(previous_entry.path.clone());
            entries.push(ManifestEntry {
                path: previous_entry.path,
                entry_type: previous_entry.entry_type,
                size: 0,
                executable: previous_entry.executable,
                hash: previous_entry.hash,
                target: previous_entry.target,
                state: EntryState::Removed,
            });
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));

        let root_digest = compute_root_digest_from_entries(&entries);

        let manifest = Manifest {
            format_version: 1,
            tag: self.tag.to_string(),
            root: ManifestRoot {
                digest: root_digest,
                algo: "sha256".to_string(),
            },
            summary: ManifestSummary {
                file_count: draft.entry_count,
                raw_size: draft.raw_size,
                changed_count: (changed_paths.len() + new_paths.len()) as u64,
                removed_count: removed_paths.len() as u64,
            },
            entry: None,
            archive: None,
            files: entries,
            encryption: None,
            signature: None,
        };

        Ok(DiffOutcome {
            manifest,
            changed_paths,
            new_paths,
            removed_paths,
            unchanged_paths,
        })
    }
}

fn metadata_equal(descriptor: &FileDescriptor, previous: &ManifestEntry) -> bool {
    descriptor.entry_type == previous.entry_type
        && descriptor.size == previous.size
        && descriptor.executable == previous.executable
        && descriptor.target == previous.target
        && descriptor.hash == previous.hash
}

pub fn compute_digest_from_draft(draft: &ManifestDraft) -> String {
    let mut entries: Vec<ManifestEntry> = draft
        .descriptors
        .iter()
        .map(|desc| ManifestEntry {
            path: desc.path.clone(),
            entry_type: desc.entry_type,
            size: desc.size,
            executable: desc.executable,
            hash: desc.hash.clone(),
            target: desc.target.clone(),
            state: EntryState::Present,
        })
        .collect();

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    compute_root_digest_from_entries(&entries)
}

pub fn compute_root_digest_from_entries(entries: &[ManifestEntry]) -> String {
    let mut hasher = Sha256::new();

    for entry in entries {
        if entry.state != EntryState::Present {
            continue;
        }
        hasher.update(entry.path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.entry_type.as_str().as_bytes());
        if let Some(target) = &entry.target {
            hasher.update(target.as_bytes());
        }
        if let Some(hash) = &entry.hash {
            hasher.update(hash.as_bytes());
        }
        hasher.update([0xff]);
    }

    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!("{SHA256_PREFIX}{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{EntryState, EntryType};

    #[test]
    fn manifest_digest_changes_when_hash_differs() {
        let draft_a = ManifestDraft {
            descriptors: vec![FileDescriptor {
                path: "foo".to_string(),
                entry_type: EntryType::File,
                size: 12,
                executable: Some(false),
                target: None,
                hash: Some("blake3:aaa".to_string()),
            }],
            raw_size: 12,
            entry_count: 1,
        };

        let draft_b = ManifestDraft {
            descriptors: vec![FileDescriptor {
                path: "foo".to_string(),
                entry_type: EntryType::File,
                size: 12,
                executable: Some(false),
                target: None,
                hash: Some("blake3:bbb".to_string()),
            }],
            raw_size: 12,
            entry_count: 1,
        };

        let digest_a = compute_digest_from_draft(&draft_a);
        let digest_b = compute_digest_from_draft(&draft_b);
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn metadata_equal_respects_hash() {
        let descriptor = FileDescriptor {
            path: "foo".to_string(),
            entry_type: EntryType::File,
            size: 1,
            executable: Some(false),
            target: None,
            hash: Some("blake3:aaa".to_string()),
        };
        let mut previous = ManifestEntry {
            path: "foo".to_string(),
            entry_type: EntryType::File,
            size: 1,
            executable: Some(false),
            hash: Some("blake3:aaa".to_string()),
            target: None,
            state: EntryState::Present,
        };
        assert!(metadata_equal(&descriptor, &previous));

        previous.hash = Some("blake3:bbb".to_string());
        assert!(!metadata_equal(&descriptor, &previous));
    }
}

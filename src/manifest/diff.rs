use std::collections::BTreeMap;

use super::builder::{FileDescriptor, ManifestDraft};
use super::model::{EntryState, Manifest, ManifestEntry, ManifestRoot, ManifestSummary};
use anyhow::Result;
use sha2::{Digest, Sha256};

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
                mode: descriptor.mode,
                hash: None,
                spans: None,
                target: descriptor.target,
                state: EntryState::Present,
                storage: None,
            });
        }

        for (_path, previous_entry) in previous_map.into_iter() {
            removed_paths.push(previous_entry.path.clone());
            entries.push(ManifestEntry {
                path: previous_entry.path,
                entry_type: previous_entry.entry_type,
                size: 0,
                mode: previous_entry.mode,
                hash: None,
                spans: None,
                target: previous_entry.target,
                state: EntryState::Removed,
                storage: None,
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
            chunks: vec![],
            packs: vec![],
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
        && descriptor.mode == previous.mode
        && descriptor.target == previous.target
}

pub fn compute_digest_from_draft(draft: &ManifestDraft) -> String {
    let mut entries: Vec<ManifestEntry> = draft
        .descriptors
        .iter()
        .map(|desc| ManifestEntry {
            path: desc.path.clone(),
            entry_type: desc.entry_type,
            size: desc.size,
            mode: desc.mode,
            hash: None,
            spans: None,
            target: desc.target.clone(),
            state: EntryState::Present,
            storage: None,
        })
        .collect();

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    compute_root_digest_from_entries(&entries)
}

pub fn compute_root_digest_from_entries(entries: &[ManifestEntry]) -> String {
    let mut hasher = Sha256::new();

    for entry in entries {
        hasher.update(entry.path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.entry_type.as_str().as_bytes());
        hasher.update(entry.size.to_le_bytes());
        hasher.update(entry.mode.to_le_bytes());
        if let Some(target) = &entry.target {
            hasher.update(target.as_bytes());
        }
        hasher.update(entry.state.as_str().as_bytes());
        hasher.update([0xff]);
    }

    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

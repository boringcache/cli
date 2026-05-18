use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub const FORMAT_VERSION: u32 = 2;
pub const ADAPTER: &str = "pkg-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkgCompatibility {
    pub runtime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_abi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockfile_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkgPointerBlob {
    pub digest: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkgPointerPackage {
    pub package_key: String,
    pub blob_digest: String,
    pub install_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_integrity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PkgFixup {
    Dir { rel: String },
    Symlink { link_rel: String, target: String },
    StateFile { rel: String, blob_digest: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkgPointer {
    pub format_version: u32,
    pub adapter: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_root_rel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<PkgCompatibility>,
    pub packages: Vec<PkgPointerPackage>,
    pub fixups: Vec<PkgFixup>,
    pub blobs: Vec<PkgPointerBlob>,
}

pub fn build_pointer(scan: &super::PkgLayoutScan) -> Result<Vec<u8>> {
    let pointer = PkgPointer {
        format_version: FORMAT_VERSION,
        adapter: ADAPTER.to_string(),
        ecosystem: scan.ecosystem.clone(),
        install_root_rel: None,
        compatibility: scan.compatibility.clone(),
        packages: scan.packages.clone(),
        fixups: scan.fixups.clone(),
        blobs: scan
            .blobs
            .iter()
            .enumerate()
            .map(|(index, blob)| PkgPointerBlob {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
                sequence: Some(index as u64),
            })
            .collect(),
    };

    serde_json::to_vec(&pointer).context("Failed to serialize package CAS pointer")
}

pub fn parse_pointer(bytes: &[u8]) -> Result<PkgPointer> {
    let pointer: PkgPointer =
        serde_json::from_slice(bytes).context("Failed to parse package CAS pointer")?;

    if pointer.format_version != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported package CAS pointer version {}",
            pointer.format_version
        ));
    }
    if pointer.adapter != ADAPTER {
        return Err(anyhow!(
            "Unsupported package CAS pointer adapter '{}'",
            pointer.adapter
        ));
    }
    if pointer.ecosystem.trim().is_empty() {
        return Err(anyhow!("Package CAS pointer is missing ecosystem"));
    }

    let mut blob_sizes = HashMap::new();
    for blob in &pointer.blobs {
        if !crate::cas_oci::is_valid_sha256_digest(&blob.digest) {
            return Err(anyhow!("Invalid package CAS blob digest '{}'", blob.digest));
        }
        blob_sizes.insert(blob.digest.as_str(), blob.size_bytes);
    }

    for package in &pointer.packages {
        if package.package_key.trim().is_empty() {
            return Err(anyhow!("Package CAS entry is missing package_key"));
        }
        if !blob_sizes.contains_key(package.blob_digest.as_str()) {
            return Err(anyhow!(
                "Package CAS pointer missing blob metadata for package {} digest {}",
                package.package_key,
                package.blob_digest
            ));
        }
        if package.install_paths.is_empty() {
            return Err(anyhow!(
                "Package CAS entry {} has no install paths",
                package.package_key
            ));
        }
        for install_path in &package.install_paths {
            validate_relative_path("package install path", install_path)?;
        }
    }

    for fixup in &pointer.fixups {
        match fixup {
            PkgFixup::Dir { rel } => validate_relative_path("package CAS dir fixup", rel)?,
            PkgFixup::Symlink { link_rel, target } => {
                validate_relative_path("package CAS symlink fixup", link_rel)?;
                if target.is_empty() {
                    return Err(anyhow!(
                        "Package CAS symlink fixup {} has empty target",
                        link_rel
                    ));
                }
            }
            PkgFixup::StateFile { rel, blob_digest } => {
                validate_relative_path("package CAS state-file fixup", rel)?;
                if !blob_sizes.contains_key(blob_digest.as_str()) {
                    return Err(anyhow!(
                        "Package CAS state-file fixup {} references missing blob {}",
                        rel,
                        blob_digest
                    ));
                }
            }
        }
    }

    Ok(pointer)
}

fn validate_relative_path(label: &str, relative: &str) -> Result<()> {
    if relative.trim().is_empty() {
        return Err(anyhow!("{label} is empty"));
    }
    crate::cas_file::safe_join(Path::new("."), relative)
        .map(|_| ())
        .with_context(|| format!("Invalid {label}: {relative}"))
}

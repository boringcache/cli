mod bundler;
mod npm;

use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub package_key: String,
    pub lock_integrity: Option<String>,
    pub install_paths: Vec<PathBuf>,
    pub no_integrity: bool,
}

#[derive(Debug, Clone)]
pub struct DetectResult {
    pub ecosystem: &'static str,
    pub lockfile: PathBuf,
    pub install_root: PathBuf,
}

pub struct DetectedPkgLayout {
    pub adapter: Box<dyn PkgAdapter>,
    pub detection: DetectResult,
    pub packages: Vec<ResolvedPackage>,
}

pub trait PkgAdapter: Send + Sync {
    fn ecosystem(&self) -> &'static str;
    fn detect(&self, save_path: &Path) -> Option<DetectResult>;
    fn enumerate(&self, detection: &DetectResult) -> Result<Vec<ResolvedPackage>>;
    fn compatibility(
        &self,
        detection: &DetectResult,
    ) -> Result<Option<crate::cache::cas_pkg::PkgCompatibility>>;
}

pub fn detect_pkg_layout(save_path: &Path) -> Option<DetectedPkgLayout> {
    let adapters: Vec<Box<dyn PkgAdapter>> =
        vec![Box::new(bundler::BundlerAdapter), Box::new(npm::NpmAdapter)];

    for adapter in adapters {
        let Some(detection) = adapter.detect(save_path) else {
            continue;
        };
        let packages = adapter.enumerate(&detection).ok()?;
        if packages.is_empty() {
            continue;
        }
        return Some(DetectedPkgLayout {
            adapter,
            detection,
            packages,
        });
    }

    None
}

pub fn has_pkg_layout(save_path: &Path) -> bool {
    detect_pkg_layout(save_path).is_some()
}

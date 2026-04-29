use std::collections::BTreeMap;
use std::path::Path;

use crate::project_config;
use crate::ui;

pub(super) fn cache_env_for_project(project_dir: &Path) -> BTreeMap<String, String> {
    let Some(entry_id) = detect_cache_entry(project_dir) else {
        return BTreeMap::new();
    };
    let entries = vec![entry_id.to_string()];

    match project_config::resolve_run_plan(project_dir, &[], &entries, &[]) {
        Ok(plan) => plan.env_vars,
        Err(error) => {
            ui::warn(&format!(
                "Could not resolve Node package-manager cache env for {entry_id}: {error:#}"
            ));
            BTreeMap::new()
        }
    }
}

fn detect_cache_entry(project_dir: &Path) -> Option<&'static str> {
    if let Some(package_manager) = detect_package_json_manager(project_dir) {
        return Some(package_manager.cache_entry());
    }

    if project_dir.join("pnpm-lock.yaml").exists() {
        return Some(NodePackageManager::Pnpm.cache_entry());
    }
    if project_dir.join("yarn.lock").exists() {
        return Some(NodePackageManager::Yarn.cache_entry());
    }
    if project_dir.join("package-lock.json").exists()
        || project_dir.join("npm-shrinkwrap.json").exists()
    {
        return Some(NodePackageManager::Npm.cache_entry());
    }
    if project_dir.join("package.json").exists() {
        return Some(NodePackageManager::Npm.cache_entry());
    }

    None
}

fn detect_package_json_manager(project_dir: &Path) -> Option<NodePackageManager> {
    let package_json = std::fs::read_to_string(project_dir.join("package.json")).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&package_json).ok()?;
    let package_manager = parsed.get("packageManager")?.as_str()?.trim();
    let separator = package_manager.rfind('@')?;
    if separator == 0 {
        return None;
    }
    NodePackageManager::from_name(&package_manager[..separator])
}

#[derive(Debug, Clone, Copy)]
enum NodePackageManager {
    Npm,
    Pnpm,
    Yarn,
}

impl NodePackageManager {
    fn from_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "npm" => Some(Self::Npm),
            "pnpm" => Some(Self::Pnpm),
            "yarn" => Some(Self::Yarn),
            _ => None,
        }
    }

    fn cache_entry(self) -> &'static str {
        match self {
            Self::Npm => "npm-cache",
            Self::Pnpm => "pnpm-store",
            Self::Yarn => "yarn-cache",
        }
    }
}

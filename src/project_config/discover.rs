use anyhow::{Context, Result};
use std::path::Path;

use super::{LoadedRepoConfig, RepoConfig};

const PROJECT_CONFIG_FILE_NAMES: &[&str] = &[".boringcache.toml"];

pub fn discover(start_dir: &Path) -> Result<Option<LoadedRepoConfig>> {
    for directory in start_dir.ancestors() {
        for file_name in PROJECT_CONFIG_FILE_NAMES {
            let path = directory.join(file_name);
            if !path.exists() {
                continue;
            }

            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            let config: RepoConfig = toml::from_str(&contents)
                .with_context(|| format!("Failed to parse {}", path.display()))?;

            return Ok(Some(LoadedRepoConfig {
                root: directory.to_path_buf(),
                path,
                config,
            }));
        }
    }

    Ok(None)
}

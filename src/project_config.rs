use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const PROJECT_CONFIG_FILE_NAMES: &[&str] = &[".boringcache.toml", "boringcache.toml"];

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RepoConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entries: BTreeMap<String, RepoEntryConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, RepoProfileConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapters: BTreeMap<String, AdapterConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepoEntryConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RepoProfileConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AdapterCommandConfig {
    String(String),
    Array(Vec<String>),
}

impl AdapterCommandConfig {
    pub fn argv(&self) -> Result<Vec<String>> {
        match self {
            AdapterCommandConfig::String(value) => shlex::split(value)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse adapter command string: {value}")),
            AdapterCommandConfig::Array(argv) => Ok(argv.clone()),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AdapterConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<AdapterCommandConfig>,
    #[serde(default)]
    pub no_platform: bool,
    #[serde(default)]
    pub no_git: bool,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    #[serde(rename = "cache-mode", skip_serializing_if = "Option::is_none")]
    pub cache_mode: Option<String>,
    #[serde(rename = "cache-ref-tag", skip_serializing_if = "Option::is_none")]
    pub cache_ref_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(rename = "endpoint-host", skip_serializing_if = "Option::is_none")]
    pub endpoint_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct LoadedRepoConfig {
    pub path: PathBuf,
    pub root: PathBuf,
    pub config: RepoConfig,
}

#[derive(Debug, Clone)]
pub struct ResolvedAdapterConfig {
    pub loaded_config: Option<LoadedRepoConfig>,
    pub adapter_config: Option<AdapterConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedRunPlan {
    pub workspace: Option<String>,
    pub repo_config_path: Option<PathBuf>,
    pub tag_path_pairs: Vec<String>,
    pub env_vars: BTreeMap<String, String>,
    pub archive_entries: Vec<ResolvedRunEntryPlan>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RunEntryRequestSource {
    Profile,
    Entry,
    CommandInferred,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RunEntryResolutionSource {
    RepoConfig,
    BuiltIn,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResolvedRunEntryPlan {
    pub requested: String,
    pub request_source: RunEntryRequestSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub resolution_source: RunEntryResolutionSource,
    pub tag: String,
    pub path: String,
    pub tag_path_pair: String,
}

#[derive(Debug, Clone, Copy)]
enum DefaultPathKind {
    Relative(&'static str),
    Home(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct BuiltInEntrySpec {
    default_tag: &'static str,
    env_lookup: &'static [&'static str],
    env_export: &'static [&'static str],
    extra_env: &'static [(&'static str, &'static str)],
    default_path: DefaultPathKind,
}

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

pub fn resolve_adapter_config(
    start_dir: &Path,
    adapter_name: &str,
) -> Result<ResolvedAdapterConfig> {
    let loaded_config = discover(start_dir)?;
    let adapter_config = loaded_config
        .as_ref()
        .and_then(|loaded| find_adapter(&loaded.config, adapter_name))
        .cloned();

    Ok(ResolvedAdapterConfig {
        loaded_config,
        adapter_config,
    })
}

pub fn resolve_run_plan(
    start_dir: &Path,
    requested_profiles: &[String],
    requested_entries: &[String],
    command: &[String],
) -> Result<ResolvedRunPlan> {
    let repo_config = discover(start_dir)?;
    let normalized_profiles: Vec<String> = requested_profiles
        .iter()
        .map(|value| normalize_profile_name(value))
        .filter(|value| !value.is_empty())
        .collect();
    let normalized_entries: Vec<String> = requested_entries
        .iter()
        .map(|value| canonical_entry_id(value))
        .filter(|value| !value.is_empty())
        .collect();

    let mut resolved_entries_to_request: Vec<RequestedRunEntry> = Vec::new();
    let mut seen = BTreeSet::new();

    if !normalized_profiles.is_empty() {
        let Some(loaded_config) = repo_config.as_ref() else {
            anyhow::bail!(
                "No repo cache config found. Add .boringcache.toml before using --profile."
            );
        };

        for profile_name in normalized_profiles {
            let Some(profile) = find_profile(&loaded_config.config, &profile_name) else {
                anyhow::bail!(
                    "Unknown cache profile '{}'. Defined profiles: {}",
                    profile_name,
                    available_profiles(&loaded_config.config)
                );
            };

            for entry_id in profile
                .entries
                .iter()
                .map(|entry| canonical_entry_id(entry))
            {
                if seen.insert(entry_id.clone()) {
                    resolved_entries_to_request.push(RequestedRunEntry {
                        entry_id,
                        request_source: RunEntryRequestSource::Profile,
                        profile: Some(profile_name.clone()),
                    });
                }
            }
        }
    }

    for entry_id in normalized_entries {
        if seen.insert(entry_id.clone()) {
            resolved_entries_to_request.push(RequestedRunEntry {
                entry_id,
                request_source: RunEntryRequestSource::Entry,
                profile: None,
            });
        }
    }

    if resolved_entries_to_request.is_empty() {
        for entry_id in infer_entries_from_command(command) {
            if seen.insert(entry_id.clone()) {
                resolved_entries_to_request.push(RequestedRunEntry {
                    entry_id,
                    request_source: RunEntryRequestSource::CommandInferred,
                    profile: None,
                });
            }
        }
    }

    if resolved_entries_to_request.is_empty() {
        return Ok(ResolvedRunPlan {
            workspace: repo_config
                .as_ref()
                .and_then(|loaded| sanitize_workspace(loaded.config.workspace.as_deref())),
            repo_config_path: repo_config.as_ref().map(|loaded| loaded.path.clone()),
            ..ResolvedRunPlan::default()
        });
    }

    let base_dir = repo_config
        .as_ref()
        .map(|loaded| loaded.root.as_path())
        .unwrap_or(start_dir);
    let mut tag_path_pairs = Vec::new();
    let mut env_vars = BTreeMap::new();
    let mut archive_entries = Vec::new();

    for requested_entry in resolved_entries_to_request {
        let entry_id = requested_entry.entry_id.as_str();
        let override_config = repo_config
            .as_ref()
            .and_then(|loaded| find_entry(&loaded.config, entry_id));
        let spec = builtin_entry(entry_id);

        if spec.is_none() && override_config.is_none() {
            let available = repo_config
                .as_ref()
                .map(|loaded| available_entries(&loaded.config))
                .unwrap_or_else(|| String::from("(no repo entries defined)"));
            anyhow::bail!(
                "Unknown cache entry '{}'. Built-in entries: bundler, bootsnap, mise, node_modules, npm-cache, pnpm-store, uv-cache, yarn-cache. Project entries: {}",
                entry_id,
                available
            );
        }

        let resolved = resolve_entry(
            entry_id,
            override_config,
            spec,
            base_dir,
            repo_config.as_ref().map(|loaded| loaded.path.as_path()),
        )?;
        tag_path_pairs.push(resolved.tag_path.clone());
        env_vars.extend(resolved.env_vars.clone());
        archive_entries.push(ResolvedRunEntryPlan {
            requested: requested_entry.entry_id,
            request_source: requested_entry.request_source,
            profile: requested_entry.profile,
            resolution_source: resolved.resolution_source,
            tag: resolved.tag,
            path: resolved.path,
            tag_path_pair: resolved.tag_path,
        });
    }

    Ok(ResolvedRunPlan {
        workspace: repo_config
            .as_ref()
            .and_then(|loaded| sanitize_workspace(loaded.config.workspace.as_deref())),
        repo_config_path: repo_config.as_ref().map(|loaded| loaded.path.clone()),
        tag_path_pairs,
        env_vars,
        archive_entries,
    })
}

#[derive(Debug, Clone)]
struct ResolvedEntry {
    tag: String,
    path: String,
    tag_path: String,
    env_vars: BTreeMap<String, String>,
    resolution_source: RunEntryResolutionSource,
}

#[derive(Debug, Clone)]
struct RequestedRunEntry {
    entry_id: String,
    request_source: RunEntryRequestSource,
    profile: Option<String>,
}

fn resolve_entry(
    entry_id: &str,
    override_config: Option<&RepoEntryConfig>,
    spec: Option<BuiltInEntrySpec>,
    base_dir: &Path,
    config_path: Option<&Path>,
) -> Result<ResolvedEntry> {
    let resolution_source = if override_config.is_some() {
        RunEntryResolutionSource::RepoConfig
    } else {
        RunEntryResolutionSource::BuiltIn
    };
    let tag = override_config
        .and_then(|entry| sanitize_value(entry.tag.as_deref()))
        .or_else(|| spec.map(|spec| spec.default_tag.to_string()))
        .unwrap_or_else(|| entry_id.to_string());

    let path = resolve_path(entry_id, override_config, spec, base_dir, config_path)?;
    let path_value = path.to_string_lossy().to_string();
    let mut env_vars = BTreeMap::new();

    if let Some(path_env) = override_config
        .and_then(|entry| sanitize_value(entry.path_env.as_deref()))
        .filter(|value| !value.is_empty())
    {
        env_vars.insert(path_env, path_value.clone());
    }

    if let Some(spec) = spec {
        for key in spec.env_export {
            env_vars.insert((*key).to_string(), path_value.clone());
        }
        for (key, value) in spec.extra_env {
            env_vars.insert((*key).to_string(), (*value).to_string());
        }
    }

    Ok(ResolvedEntry {
        tag: tag.clone(),
        path: path_value.clone(),
        tag_path: format!("{tag}:{path_value}"),
        env_vars,
        resolution_source,
    })
}

fn resolve_path(
    entry_id: &str,
    override_config: Option<&RepoEntryConfig>,
    spec: Option<BuiltInEntrySpec>,
    base_dir: &Path,
    config_path: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(path) = override_config
        .and_then(|entry| sanitize_value(entry.path.as_deref()))
        .filter(|value| !value.is_empty())
    {
        return Ok(resolve_path_value(&path, base_dir));
    }

    if let Some(path_env) = override_config
        .and_then(|entry| sanitize_value(entry.path_env.as_deref()))
        .filter(|value| !value.is_empty())
        && let Some(value) = crate::config::env_var(&path_env)
    {
        return Ok(resolve_path_value(&value, base_dir));
    }

    if let Some(path) = override_config
        .and_then(|entry| sanitize_value(entry.default_path.as_deref()))
        .filter(|value| !value.is_empty())
    {
        return Ok(resolve_path_value(&path, base_dir));
    }

    if let Some(spec) = spec {
        for key in spec.env_lookup {
            if let Some(value) = crate::config::env_var(key) {
                return Ok(resolve_path_value(&value, base_dir));
            }
        }

        if let Some(path) = default_path(spec.default_path, base_dir) {
            return Ok(path);
        }
    }

    let location = config_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "repo config".to_string());
    anyhow::bail!(
        "Cache entry '{}' does not define a path. Add `path`, `path_env`, or `default_path` in {}.",
        entry_id,
        location
    );
}

fn default_path(kind: DefaultPathKind, base_dir: &Path) -> Option<PathBuf> {
    match kind {
        DefaultPathKind::Relative(path) => Some(base_dir.join(path)),
        DefaultPathKind::Home(path) => dirs::home_dir().map(|home| home.join(path)),
    }
}

fn resolve_path_value(value: &str, base_dir: &Path) -> PathBuf {
    let expanded = crate::commands::utils::expand_tilde_path(value);
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn builtin_entry(entry_id: &str) -> Option<BuiltInEntrySpec> {
    let empty_env: &[&str] = &[];
    let empty_pairs: &[(&str, &str)] = &[];

    match canonical_entry_id(entry_id).as_str() {
        "bundler" => Some(BuiltInEntrySpec {
            default_tag: "bundler",
            env_lookup: &["BUNDLE_PATH"],
            env_export: &["BUNDLE_PATH"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("vendor/bundle"),
        }),
        "bootsnap" => Some(BuiltInEntrySpec {
            default_tag: "bootsnap",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("tmp/cache/bootsnap"),
        }),
        "mise" => Some(BuiltInEntrySpec {
            default_tag: "mise-installs",
            env_lookup: &["MISE_INSTALLS_DIR"],
            env_export: &["MISE_INSTALLS_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Home(".local/share/mise/installs"),
        }),
        "node_modules" => Some(BuiltInEntrySpec {
            default_tag: "node_modules",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("node_modules"),
        }),
        "pnpm-store" => Some(BuiltInEntrySpec {
            default_tag: "pnpm-store",
            env_lookup: &["PNPM_STORE_DIR", "NPM_CONFIG_STORE_DIR"],
            env_export: &["PNPM_STORE_DIR", "NPM_CONFIG_STORE_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".pnpm-store"),
        }),
        "yarn-cache" => Some(BuiltInEntrySpec {
            default_tag: "yarn-cache",
            env_lookup: &["YARN_CACHE_FOLDER"],
            env_export: &["YARN_CACHE_FOLDER"],
            extra_env: &[("YARN_ENABLE_GLOBAL_CACHE", "false")],
            default_path: DefaultPathKind::Relative(".yarn-cache"),
        }),
        "npm-cache" => Some(BuiltInEntrySpec {
            default_tag: "npm-cache",
            env_lookup: &["npm_config_cache", "NPM_CONFIG_CACHE"],
            env_export: &["npm_config_cache", "NPM_CONFIG_CACHE"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".npm-cache"),
        }),
        "uv-cache" => Some(BuiltInEntrySpec {
            default_tag: "uv-cache",
            env_lookup: &["UV_CACHE_DIR"],
            env_export: &["UV_CACHE_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".uv-cache"),
        }),
        _ => None,
    }
}

pub fn infer_entries_from_command(command: &[String]) -> Vec<String> {
    let Some(binary) = command.first() else {
        return Vec::new();
    };
    let command_name = Path::new(binary)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(binary.as_str())
        .to_ascii_lowercase();
    let subcommand = command
        .get(1)
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    match (command_name.as_str(), subcommand.as_str()) {
        ("bundle", "install") => vec!["bundler".to_string()],
        ("mise", "install") => vec!["mise".to_string()],
        ("npm", "install") | ("npm", "ci") => {
            vec!["npm-cache".to_string(), "node_modules".to_string()]
        }
        ("pnpm", "install") | ("pnpm", "i") => {
            vec!["pnpm-store".to_string(), "node_modules".to_string()]
        }
        ("yarn", "install") => vec!["yarn-cache".to_string(), "node_modules".to_string()],
        ("uv", "sync") | ("uv", "pip") => vec!["uv-cache".to_string()],
        _ => Vec::new(),
    }
}

fn find_entry<'a>(config: &'a RepoConfig, entry_id: &str) -> Option<&'a RepoEntryConfig> {
    let canonical = canonical_entry_id(entry_id);
    config
        .entries
        .iter()
        .find(|(key, _)| canonical_entry_id(key) == canonical)
        .map(|(_, value)| value)
}

fn find_profile<'a>(config: &'a RepoConfig, profile_name: &str) -> Option<&'a RepoProfileConfig> {
    let normalized = normalize_profile_name(profile_name);
    config
        .profiles
        .iter()
        .find(|(key, _)| normalize_profile_name(key) == normalized)
        .map(|(_, value)| value)
}

fn find_adapter<'a>(config: &'a RepoConfig, adapter_name: &str) -> Option<&'a AdapterConfig> {
    let normalized = normalize_key(adapter_name);
    config
        .adapters
        .iter()
        .find(|(key, _)| normalize_key(key) == normalized)
        .map(|(_, value)| value)
}

fn available_profiles(config: &RepoConfig) -> String {
    let mut names = config
        .profiles
        .keys()
        .map(|value| normalize_profile_name(value))
        .collect::<Vec<_>>();
    names.sort();
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(", ")
    }
}

fn available_entries(config: &RepoConfig) -> String {
    let mut names = config
        .entries
        .keys()
        .map(|value| canonical_entry_id(value))
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names.join(", ")
    }
}

fn sanitize_workspace(value: Option<&str>) -> Option<String> {
    sanitize_value(value)
}

fn sanitize_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub fn normalize_profile_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

pub fn canonical_entry_id(value: &str) -> String {
    match normalize_key(value).as_str() {
        "mise-installs" => "mise".to_string(),
        "npm" => "npm-cache".to_string(),
        "pnpm" => "pnpm-store".to_string(),
        "uv" => "uv-cache".to_string(),
        "yarn" => "yarn-cache".to_string(),
        "node-modules" => "node_modules".to_string(),
        other => other.to_string(),
    }
}

pub fn built_in_default_tag(entry_id: &str) -> Option<&'static str> {
    builtin_entry(entry_id).map(|spec| spec.default_tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn discovers_repo_config_from_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path().join("project");
        let nested_dir = project_dir.join("nested");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(
            project_dir.join(".boringcache.toml"),
            r#"
workspace = "org/workspace"

[entries.bundler]
tag = "bundler-gems"
"#,
        )
        .unwrap();

        let loaded = discover(&nested_dir).unwrap().unwrap();
        assert_eq!(loaded.root, project_dir);
        assert_eq!(loaded.config.workspace.as_deref(), Some("org/workspace"));
    }

    #[test]
    fn resolves_profile_entries_with_built_in_defaults() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"

[entries.bundler]
tag = "bundler-gems"

[profiles.bundle-install]
entries = ["bundler"]
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[String::from("bundle_install")],
            &[],
            &["bundle".to_string(), "install".to_string()],
        )
        .unwrap();

        assert_eq!(plan.workspace.as_deref(), Some("org/workspace"));
        assert_eq!(
            plan.tag_path_pairs,
            vec![format!(
                "bundler-gems:{}",
                temp_dir.path().join("vendor/bundle").display()
            )]
        );
        assert_eq!(
            plan.env_vars.get("BUNDLE_PATH"),
            Some(&temp_dir.path().join("vendor/bundle").display().to_string())
        );
    }

    #[test]
    fn infers_bundle_install_without_profile() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[],
            &["bundle".to_string(), "install".to_string()],
        )
        .unwrap();

        assert_eq!(plan.workspace.as_deref(), Some("org/workspace"));
        assert_eq!(
            plan.tag_path_pairs,
            vec![format!(
                "bundler:{}",
                temp_dir.path().join("vendor/bundle").display()
            )]
        );
    }

    #[test]
    fn uses_entry_default_path_override_before_built_in_default() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
[entries.mise]
default_path = "/mise/installs"
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[String::from("mise")],
            &["mise".to_string(), "install".to_string()],
        )
        .unwrap();

        assert_eq!(plan.tag_path_pairs, vec!["mise-installs:/mise/installs"]);
        assert_eq!(
            plan.env_vars.get("MISE_INSTALLS_DIR"),
            Some(&"/mise/installs".to_string())
        );
    }

    #[test]
    fn parses_adapter_config_with_command_array() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"

[adapters.turbo]
tag = "turbo-main"
command = ["pnpm", "turbo", "run", "build"]
entries = ["pnpm-store"]
profiles = ["bundle-install"]
port = 5001
endpoint-host = "host.docker.internal"
"#,
        )
        .unwrap();

        let resolved = resolve_adapter_config(temp_dir.path(), "turbo").unwrap();
        let loaded = resolved.loaded_config.unwrap();
        let adapter = resolved.adapter_config.unwrap();

        assert_eq!(loaded.config.workspace.as_deref(), Some("org/workspace"));
        assert_eq!(adapter.tag.as_deref(), Some("turbo-main"));
        assert_eq!(adapter.entries, vec!["pnpm-store"]);
        assert_eq!(adapter.profiles, vec!["bundle-install"]);
        assert_eq!(adapter.port, Some(5001));
        assert_eq!(
            adapter.endpoint_host.as_deref(),
            Some("host.docker.internal")
        );
        assert_eq!(
            adapter.command.unwrap().argv().unwrap(),
            vec!["pnpm", "turbo", "run", "build"]
        );
    }

    #[test]
    fn parses_adapter_command_string_with_shlex() {
        let command = AdapterCommandConfig::String(
            r#"sh -c 'pnpm install --frozen-lockfile && pnpm turbo run build'"#.to_string(),
        );

        assert_eq!(
            command.argv().unwrap(),
            vec![
                "sh",
                "-c",
                "pnpm install --frozen-lockfile && pnpm turbo run build"
            ]
        );
    }

    #[test]
    fn adapter_resolution_preserves_loaded_config_when_adapter_missing() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"
"#,
        )
        .unwrap();

        let resolved = resolve_adapter_config(temp_dir.path(), "turbo").unwrap();
        assert!(resolved.loaded_config.is_some());
        assert!(resolved.adapter_config.is_none());
    }
}

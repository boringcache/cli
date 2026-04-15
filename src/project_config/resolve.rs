use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::builtins::{
    BuiltInEntrySpec, DefaultPathKind, builtin_entry, canonical_entry_id,
    infer_entries_from_command, normalize_key, normalize_profile_name,
};
use super::discover::discover;
use super::model::{
    AdapterConfig, RepoConfig, RepoEntryConfig, RepoProfileConfig, ResolvedAdapterConfig,
    ResolvedRunEntryPlan, ResolvedRunPlan, RunEntryRequestSource, RunEntryResolutionSource,
};

pub fn prefer_cli_scalar<T>(configured: Option<T>, cli: Option<T>) -> Option<T> {
    cli.or(configured)
}

pub fn prefer_cli_list<F>(configured: &[String], cli: &[String], normalize: F) -> Vec<String>
where
    F: Fn(&str) -> String,
{
    let source = if cli.is_empty() { configured } else { cli };
    let mut values = Vec::new();
    let mut seen = BTreeSet::new();

    for value in source {
        let normalized = normalize(value);
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            values.push(normalized);
        }
    }

    values
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
                "Unknown cache entry '{}'. Built-in entries: bundler, bootsnap, composer-cache, go-build-cache, go-mod-cache, mise, node_modules, npm-cache, pnpm-store, uv-cache, vendor, yarn-cache. Project entries: {}",
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

        if let Some(path) = dynamic_builtin_path(entry_id, base_dir) {
            return Ok(path);
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

fn dynamic_builtin_path(entry_id: &str, base_dir: &Path) -> Option<PathBuf> {
    match canonical_entry_id(entry_id).as_str() {
        "composer-cache" => read_composer_config_path(base_dir, "cache-dir"),
        "vendor" => read_composer_config_path(base_dir, "vendor-dir"),
        _ => None,
    }
}

fn read_composer_config_path(base_dir: &Path, key: &str) -> Option<PathBuf> {
    let composer_json = std::fs::read_to_string(base_dir.join("composer.json")).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&composer_json).ok()?;
    let config = parsed.get("config")?.as_object()?;
    let value = config.get(key)?.as_str()?;
    Some(resolve_path_value(value, base_dir))
}

fn resolve_path_value(value: &str, base_dir: &Path) -> PathBuf {
    let expanded = crate::command_support::expand_tilde_path(value);
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
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

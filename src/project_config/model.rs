use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RepoConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "RepoProxyConfig::is_empty")]
    pub proxy: RepoProxyConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub entries: BTreeMap<String, RepoEntryConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, RepoProfileConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapters: BTreeMap<String, AdapterConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip: Vec<SkipRuleConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RepoProxyConfig {
    #[serde(
        default,
        rename = "metadata-hints",
        alias = "metadata_hints",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub metadata_hints: Vec<String>,
}

impl RepoProxyConfig {
    pub fn is_empty(&self) -> bool {
        self.metadata_hints.is_empty()
    }
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

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkipRuleConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    #[serde(default, rename = "no-platform", alias = "no_platform")]
    pub no_platform: bool,
    #[serde(default, rename = "no-git", alias = "no_git")]
    pub no_git: bool,
    #[serde(default, rename = "read-only", alias = "read_only")]
    pub read_only: bool,
    #[serde(default, rename = "fail-on-cache-error", alias = "fail_on_cache_error")]
    pub fail_on_cache_error: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    #[serde(
        default,
        rename = "metadata-hints",
        alias = "metadata_hints",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub metadata_hints: Vec<String>,
    #[serde(default, rename = "skip-restore", alias = "skip_restore")]
    pub skip_restore: bool,
    #[serde(default, rename = "skip-save", alias = "skip_save")]
    pub skip_save: bool,
    #[serde(default, rename = "save-on-failure", alias = "save_on_failure")]
    pub save_on_failure: bool,
    #[serde(
        rename = "cache-mode",
        alias = "cache_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_mode: Option<String>,
    #[serde(
        rename = "cache-ref-tag",
        alias = "cache_ref_tag",
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_ref_tag: Option<String>,
    #[serde(
        rename = "cache-run-ref-tag",
        alias = "cache_run_ref_tag",
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_run_ref_tag: Option<String>,
    #[serde(
        default,
        rename = "cache-from-ref-tags",
        alias = "cache_from_ref_tags",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cache_from_ref_tags: Vec<String>,
    #[serde(
        default,
        rename = "cache-promote-ref-tags",
        alias = "cache_promote_ref_tags",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub cache_promote_ref_tags: Vec<String>,
    #[serde(
        rename = "sccache-key-prefix",
        alias = "sccache_key_prefix",
        skip_serializing_if = "Option::is_none"
    )]
    pub sccache_key_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(
        rename = "endpoint-host",
        alias = "endpoint_host",
        skip_serializing_if = "Option::is_none"
    )]
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
    pub proxy_metadata_hints: Vec<String>,
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

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::cli::AdapterArgs;
use crate::commands::{proxy_exec, restore, save, serve, utils};
use crate::config::{AuthPurpose, Config};
use crate::exit_code::ExitCodeError;
use crate::project_config;
use crate::ui;

const EXIT_CONFIG: i32 = 78;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterKind {
    Turbo,
    Nx,
    Bazel,
    Gradle,
    Maven,
    Sccache,
    Go,
    Docker,
}

impl AdapterKind {
    pub fn toml_key(self) -> &'static str {
        match self {
            AdapterKind::Turbo => "turbo",
            AdapterKind::Nx => "nx",
            AdapterKind::Bazel => "bazel",
            AdapterKind::Gradle => "gradle",
            AdapterKind::Maven => "maven",
            AdapterKind::Sccache => "sccache",
            AdapterKind::Go => "go",
            AdapterKind::Docker => "docker",
        }
    }

    fn display_name(self) -> &'static str {
        self.toml_key()
    }

    fn proxy_env_plan(self, context: &proxy_exec::ProxyContext) -> ProxyEnvPlan {
        let mut set = BTreeMap::new();
        let endpoint = context.endpoint();

        set.insert(
            "BORINGCACHE_PROXY_PORT".to_string(),
            context.port.to_string(),
        );
        set.insert(
            "BORINGCACHE_CACHE_REF".to_string(),
            context.cache_ref.clone(),
        );

        match self {
            AdapterKind::Turbo => {
                set.insert("TURBO_API".to_string(), endpoint);
                set.insert(
                    "TURBO_TOKEN".to_string(),
                    proxy_exec::PROXY_AUTH_TOKEN.to_string(),
                );
                set.insert(
                    "TURBO_TEAM".to_string(),
                    proxy_exec::PROXY_AUTH_TOKEN.to_string(),
                );
            }
            AdapterKind::Nx => {
                set.insert("NX_SELF_HOSTED_REMOTE_CACHE_SERVER".to_string(), endpoint);
                set.insert(
                    "NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN".to_string(),
                    proxy_exec::PROXY_AUTH_TOKEN.to_string(),
                );
            }
            AdapterKind::Sccache => {
                set.insert("RUSTC_WRAPPER".to_string(), "sccache".to_string());
                set.insert(
                    "SCCACHE_WEBDAV_ENDPOINT".to_string(),
                    format!("{endpoint}/"),
                );
            }
            AdapterKind::Go => {
                set.insert(
                    "GOCACHEPROG".to_string(),
                    format!("boringcache go-cacheprog --endpoint {endpoint}"),
                );
            }
            AdapterKind::Bazel | AdapterKind::Gradle | AdapterKind::Maven | AdapterKind::Docker => {
            }
        }

        ProxyEnvPlan { set }
    }

    fn inject_proxy_env(
        self,
        command: &mut tokio::process::Command,
        context: &proxy_exec::ProxyContext,
    ) {
        let plan = self.proxy_env_plan(context);
        command.envs(plan.set);
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProxyEnvPlan {
    set: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct DryRunPlan {
    adapter: AdapterKind,
    workspace: String,
    workspace_source: DryRunWorkspaceSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_config_path: Option<String>,
    tag: String,
    command: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    archive_entries: Vec<DryRunArchiveEntry>,
    env_vars: BTreeMap<String, String>,
    proxy: DryRunProxyPlan,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DryRunWorkspaceSource {
    Explicit,
    RepoConfig,
    ConfiguredDefault,
}

#[derive(Debug, Clone, Serialize)]
struct DryRunArchiveEntry {
    requested: String,
    request_source: DryRunArchiveEntryRequestSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    resolution_source: DryRunArchiveResolutionSource,
    tag: String,
    path: String,
    tag_path_pair: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DryRunArchiveEntryRequestSource {
    Profile,
    Entry,
    CommandInferred,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DryRunArchiveResolutionSource {
    RepoConfig,
    BuiltIn,
}

#[derive(Debug, Clone, Serialize)]
struct DryRunProxyPlan {
    host: String,
    endpoint_host: String,
    port: u16,
    read_only: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    metadata_hints: BTreeMap<String, String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn adapter_execute(
    kind: AdapterKind,
    args: AdapterArgs,
    verbose: bool,
    require_server_signature: bool,
) -> Result<()> {
    if args.json && !args.dry_run {
        anyhow::bail!(
            "--json is only supported with --dry-run for `boringcache {}`.",
            kind.display_name()
        );
    }

    let current_dir = std::env::current_dir().context("Failed to determine current directory")?;
    let resolved_adapter = project_config::resolve_adapter_config(&current_dir, kind.toml_key())?;
    let loaded_config = resolved_adapter.loaded_config;
    let adapter_config = resolved_adapter.adapter_config.unwrap_or_default();

    let project_workspace = loaded_config
        .as_ref()
        .and_then(|loaded| trim_non_empty(loaded.config.workspace.as_deref()))
        .map(ToOwned::to_owned);
    let explicit_workspace = trim_non_empty(args.workspace.as_deref()).map(ToOwned::to_owned);
    let workspace = utils::get_workspace_name_with_fallback(
        explicit_workspace.clone(),
        project_workspace.clone(),
    )?;
    let workspace_source = if explicit_workspace.is_some() {
        DryRunWorkspaceSource::Explicit
    } else if project_workspace.is_some() {
        DryRunWorkspaceSource::RepoConfig
    } else {
        DryRunWorkspaceSource::ConfiguredDefault
    };

    let tag = trim_non_empty(args.tag.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| trim_non_empty(adapter_config.tag.as_deref()).map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("Missing cache tag. Pass --tag or configure [adapters.{}].tag in .boringcache.toml.", kind.toml_key()))?;

    let command = if !args.command.is_empty() {
        args.command.clone()
    } else if let Some(command) = adapter_config.command.as_ref() {
        command.argv()?
    } else {
        Vec::new()
    };
    if command.is_empty() {
        anyhow::bail!(
            "Missing command. Pass one after -- or configure [adapters.{}].command in .boringcache.toml.",
            kind.toml_key()
        );
    }

    let no_platform = adapter_config.no_platform || args.no_platform;
    let no_git = adapter_config.no_git || args.no_git;
    let configured_read_only = adapter_config.read_only || args.read_only;
    let bind_host = trim_non_empty(args.host.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| trim_non_empty(adapter_config.host.as_deref()).map(ToOwned::to_owned))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let endpoint_host_override = trim_non_empty(args.endpoint_host.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| trim_non_empty(adapter_config.endpoint_host.as_deref()).map(ToOwned::to_owned));
    let advertised_endpoint_host = endpoint_host_override.clone().unwrap_or_else(|| {
        if bind_host == "0.0.0.0" {
            "127.0.0.1".to_string()
        } else {
            bind_host.clone()
        }
    });
    let port = args.port.or(adapter_config.port).unwrap_or(5000);

    let fail_on_cache_error = adapter_config.fail_on_cache_error || args.fail_on_cache_error;
    let skip_restore = adapter_config.skip_restore || args.skip_restore;
    let skip_save = adapter_config.skip_save || args.skip_save;
    let save_on_failure = adapter_config.save_on_failure || args.save_on_failure;
    let metadata_hint_args =
        merge_metadata_hints(&adapter_config.metadata_hints, &args.metadata_hint);
    let profile_requests = merge_profiles(&adapter_config.profiles, &args.profile);
    let entry_requests = merge_entries(&adapter_config.entries, &args.entry);
    let infer_entries = profile_requests.is_empty() && entry_requests.is_empty();
    let resolved_plan = project_config::resolve_run_plan(
        &current_dir,
        &profile_requests,
        &entry_requests,
        if infer_entries { &command } else { &[] },
    )?;
    let archive_enabled = !resolved_plan.tag_path_pairs.is_empty();
    let proxy_metadata_hints = serve::resolve_proxy_metadata_hints(&metadata_hint_args)?;

    let effective_read_only = serve::effective_proxy_read_only(configured_read_only);
    let effective_skip_save = skip_save || effective_read_only;
    let docker_cache_mode = args
        .cache_mode
        .clone()
        .or(adapter_config.cache_mode.clone())
        .unwrap_or_else(|| "max".to_string());
    let docker_cache_ref_tag = args
        .cache_ref_tag
        .clone()
        .or(adapter_config.cache_ref_tag.clone())
        .unwrap_or_else(|| "buildcache".to_string());
    validate_docker_cache_mode(&docker_cache_mode)?;

    let preview_context = proxy_exec::ProxyContext {
        endpoint_host: advertised_endpoint_host.clone(),
        port,
        cache_ref: "{CACHE_REF}".to_string(),
    };
    let preview_command = proxy_exec::substitute_proxy_placeholders(
        &prepare_command_for_execution(
            kind,
            &command,
            Some(&preview_context),
            &docker_cache_ref_tag,
            &docker_cache_mode,
            effective_read_only,
        )?,
        &preview_context,
    );
    let mut preview_env_vars = resolved_plan.env_vars.clone();
    preview_env_vars.extend(kind.proxy_env_plan(&preview_context).set);

    if args.dry_run {
        let plan = DryRunPlan {
            adapter: kind,
            workspace,
            workspace_source,
            repo_config_path: loaded_config
                .as_ref()
                .map(|loaded| loaded.path.display().to_string()),
            tag,
            command: preview_command,
            archive_entries: resolved_plan
                .archive_entries
                .into_iter()
                .map(|entry| DryRunArchiveEntry {
                    requested: entry.requested,
                    request_source: match entry.request_source {
                        project_config::RunEntryRequestSource::Profile => {
                            DryRunArchiveEntryRequestSource::Profile
                        }
                        project_config::RunEntryRequestSource::Entry => {
                            DryRunArchiveEntryRequestSource::Entry
                        }
                        project_config::RunEntryRequestSource::CommandInferred => {
                            DryRunArchiveEntryRequestSource::CommandInferred
                        }
                    },
                    profile: entry.profile,
                    resolution_source: match entry.resolution_source {
                        project_config::RunEntryResolutionSource::RepoConfig => {
                            DryRunArchiveResolutionSource::RepoConfig
                        }
                        project_config::RunEntryResolutionSource::BuiltIn => {
                            DryRunArchiveResolutionSource::BuiltIn
                        }
                    },
                    tag: entry.tag,
                    path: entry.path,
                    tag_path_pair: entry.tag_path_pair,
                })
                .collect(),
            env_vars: preview_env_vars,
            proxy: DryRunProxyPlan {
                host: bind_host,
                endpoint_host: advertised_endpoint_host,
                port,
                read_only: effective_read_only,
                metadata_hints: proxy_metadata_hints,
            },
        };

        if args.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            print_dry_run(&plan, effective_skip_save, skip_restore, save_on_failure);
        }
        return Ok(());
    }

    let has_restore_auth = Config::load_for_auth_purpose(AuthPurpose::Restore).is_ok();
    if !has_restore_auth {
        ui::info("[boringcache] No token found — running command without caching");
        let child_outcome =
            proxy_exec::spawn_command(&command, &resolved_plan.env_vars, None, |_, _| {}).await?;
        return match child_outcome {
            proxy_exec::ChildOutcome::Exited(status) => {
                let code = proxy_exec::status_exit_code(&status);
                if code == 0 {
                    Ok(())
                } else {
                    Err(ExitCodeError::silent(code).into())
                }
            }
        };
    }

    if effective_read_only && !configured_read_only {
        ui::info("[boringcache] No save-capable token found — running proxy in read-only mode");
    }
    if effective_read_only && archive_enabled && !skip_save {
        ui::info("[boringcache] Read-only mode enabled — skipping archive save phase");
    }

    if archive_enabled && !skip_restore {
        let restore_result = restore::execute_batch_restore(
            Some(workspace.clone()),
            resolved_plan.tag_path_pairs.clone(),
            verbose,
            no_platform,
            no_git,
            false,
            false,
            None,
            fail_on_cache_error,
            require_server_signature,
        )
        .await;

        if let Err(error) = restore_result {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
    }

    let proxy_handle = serve::start_proxy_background(
        workspace.clone(),
        tag,
        bind_host,
        port,
        no_platform,
        no_git,
        endpoint_host_override,
        proxy_metadata_hints,
        fail_on_cache_error,
        effective_read_only,
    )
    .await
    .map_err(|error| ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)))?;

    let proxy_context = proxy_exec::ProxyContext {
        endpoint_host: proxy_handle.endpoint_host().to_string(),
        port: proxy_handle.port(),
        cache_ref: proxy_handle.cache_ref(),
    };
    let command_to_run = prepare_command_for_execution(
        kind,
        &command,
        Some(&proxy_context),
        &docker_cache_ref_tag,
        &docker_cache_mode,
        effective_read_only,
    )?;

    let child_outcome = proxy_exec::spawn_command(
        &command_to_run,
        &resolved_plan.env_vars,
        Some(&proxy_context),
        |process, context| kind.inject_proxy_env(process, context),
    )
    .await;

    let child_outcome = match child_outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            shutdown_proxy_handle(proxy_handle, fail_on_cache_error, false).await?;
            return Err(error);
        }
    };

    match child_outcome {
        proxy_exec::ChildOutcome::Exited(status) => {
            let command_succeeded = status.success();
            let command_exit_code = proxy_exec::status_exit_code(&status);

            if archive_enabled && !effective_skip_save && (command_succeeded || save_on_failure) {
                let save_result = save::execute_batch_save(
                    Some(workspace),
                    resolved_plan.tag_path_pairs,
                    verbose,
                    no_platform,
                    no_git,
                    false,
                    Vec::new(),
                    None,
                    fail_on_cache_error,
                )
                .await;

                if let Err(error) = save_result
                    && fail_on_cache_error
                    && command_succeeded
                {
                    shutdown_proxy_handle(proxy_handle, fail_on_cache_error, false).await?;
                    return Err(
                        ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into(),
                    );
                }
            }

            shutdown_proxy_handle(proxy_handle, fail_on_cache_error, command_succeeded).await?;

            if command_exit_code == 0 {
                Ok(())
            } else {
                Err(ExitCodeError::silent(command_exit_code).into())
            }
        }
    }
}

fn trim_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn merge_entries(configured: &[String], cli: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();

    for value in configured.iter().chain(cli.iter()) {
        let normalized = project_config::canonical_entry_id(value);
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            merged.push(normalized);
        }
    }

    merged
}

fn merge_profiles(configured: &[String], cli: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();

    for value in configured.iter().chain(cli.iter()) {
        let normalized = project_config::normalize_profile_name(value);
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            merged.push(normalized);
        }
    }

    merged
}

fn merge_metadata_hints(configured: &[String], cli: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    merged.extend(configured.iter().cloned());
    merged.extend(cli.iter().cloned());
    merged
}

fn validate_docker_cache_mode(value: &str) -> Result<()> {
    if matches!(value, "max" | "min") {
        Ok(())
    } else {
        anyhow::bail!("Invalid --cache-mode '{value}'. Expected 'max' or 'min'.");
    }
}

fn prepare_command_for_execution(
    kind: AdapterKind,
    command: &[String],
    proxy_context: Option<&proxy_exec::ProxyContext>,
    cache_ref_tag: &str,
    cache_mode: &str,
    read_only: bool,
) -> Result<Vec<String>> {
    match kind {
        AdapterKind::Docker => {
            inject_docker_cache_flags(command, proxy_context, cache_ref_tag, cache_mode, read_only)
        }
        _ => Ok(command.to_vec()),
    }
}

fn inject_docker_cache_flags(
    command: &[String],
    proxy_context: Option<&proxy_exec::ProxyContext>,
    cache_ref_tag: &str,
    cache_mode: &str,
    read_only: bool,
) -> Result<Vec<String>> {
    if proxy_context.is_none() {
        return Ok(command.to_vec());
    }

    if command.len() < 4
        || command[0] != "docker"
        || command[1] != "buildx"
        || command[2] != "build"
    {
        anyhow::bail!(
            "`boringcache docker` expects `docker buildx build ...`. Pass the docker buildx command after --."
        );
    }

    if command
        .iter()
        .any(|arg| arg == "--cache-from" || arg.starts_with("--cache-from="))
        || command
            .iter()
            .any(|arg| arg == "--cache-to" || arg.starts_with("--cache-to="))
    {
        anyhow::bail!(
            "Do not pass --cache-from/--cache-to to `boringcache docker`; use --cache-ref-tag and --cache-mode instead."
        );
    }

    let context = proxy_context.expect("checked above");
    let registry_ref = format!(
        "type=registry,ref={}:{}/cache:{}",
        context.endpoint_host, context.port, cache_ref_tag
    );
    let mut prepared = command.to_vec();
    let insert_at = prepared.len() - 1;
    prepared.insert(insert_at, format!("--cache-from={registry_ref}"));
    if !read_only {
        prepared.insert(
            insert_at + 1,
            format!("--cache-to={registry_ref},mode={cache_mode}"),
        );
    }
    Ok(prepared)
}

async fn shutdown_proxy_handle(
    proxy_handle: serve::ProxyServerHandle,
    fail_on_cache_error: bool,
    allow_override: bool,
) -> Result<()> {
    if let Err(error) = proxy_handle.shutdown_and_flush().await {
        if fail_on_cache_error && allow_override {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
        ui::warn(&format!("Proxy shutdown warning: {:#}", error));
    }

    Ok(())
}

fn print_dry_run(plan: &DryRunPlan, skip_save: bool, skip_restore: bool, save_on_failure: bool) {
    ui::info(&format!(
        "[boringcache] Dry run ({})",
        plan.adapter.display_name()
    ));
    ui::info(&format!(
        "[boringcache]   proxy {}:{} (bind {}, read-only: {})",
        plan.proxy.endpoint_host,
        plan.proxy.port,
        plan.proxy.host,
        if plan.proxy.read_only { "yes" } else { "no" }
    ));

    for (key, value) in &plan.proxy.metadata_hints {
        ui::info(&format!("[boringcache]   hint {key}={value}"));
    }

    for entry in &plan.archive_entries {
        if !skip_restore {
            ui::info(&format!("[boringcache]   restore {}", entry.tag_path_pair));
        }
    }

    for (key, value) in &plan.env_vars {
        ui::info(&format!("[boringcache]   env {key}={value}"));
    }

    if !plan.command.is_empty() {
        ui::info(&format!("[boringcache]   {}", plan.command.join(" ")));
    }

    if !skip_save && !plan.archive_entries.is_empty() {
        for entry in &plan.archive_entries {
            ui::info(&format!("[boringcache]   save {}", entry.tag_path_pair));
        }
    } else if skip_save && !plan.archive_entries.is_empty() {
        ui::info("[boringcache]   # save phase skipped");
    }

    if save_on_failure && !plan.archive_entries.is_empty() && !skip_save {
        ui::info("[boringcache]   # save phase enabled for non-zero command exits");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sccache_env_plan_sets_webdav_backend() {
        let context = proxy_exec::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(&context);
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_ENDPOINT"),
            Some(&"http://127.0.0.1:5000/".to_string())
        );
        assert_eq!(plan.set.get("RUSTC_WRAPPER"), Some(&"sccache".to_string()));
    }

    #[test]
    fn docker_cache_flags_insert_before_context() {
        let context = proxy_exec::ProxyContext {
            endpoint_host: "host.docker.internal".to_string(),
            port: 5000,
            cache_ref: "{CACHE_REF}".to_string(),
        };

        let command = inject_docker_cache_flags(
            &[
                "docker".to_string(),
                "buildx".to_string(),
                "build".to_string(),
                "-t".to_string(),
                "ghcr.io/acme/app:latest".to_string(),
                "--push".to_string(),
                ".".to_string(),
            ],
            Some(&context),
            "buildcache",
            "max",
            false,
        )
        .unwrap();

        assert_eq!(command.last().map(String::as_str), Some("."));
        assert!(command.iter().any(|arg| arg
            == "--cache-from=type=registry,ref=host.docker.internal:5000/cache:buildcache"));
        assert!(command.iter().any(|arg| arg
            == "--cache-to=type=registry,ref=host.docker.internal:5000/cache:buildcache,mode=max"));
    }

    #[test]
    fn docker_cache_flags_are_read_only_when_requested() {
        let context = proxy_exec::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "{CACHE_REF}".to_string(),
        };

        let command = inject_docker_cache_flags(
            &[
                "docker".to_string(),
                "buildx".to_string(),
                "build".to_string(),
                ".".to_string(),
            ],
            Some(&context),
            "buildcache",
            "max",
            true,
        )
        .unwrap();

        assert!(
            command
                .iter()
                .any(|arg| arg == "--cache-from=type=registry,ref=127.0.0.1:5000/cache:buildcache")
        );
        assert!(!command.iter().any(|arg| arg.starts_with("--cache-to=")));
    }
}

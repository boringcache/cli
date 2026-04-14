use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::commands::{proxy_exec, restore, save, serve, utils};
use crate::config::{AuthPurpose, Config};
use crate::exit_code::ExitCodeError;
use crate::project_config;
use crate::ui;

const EXIT_CONFIG: i32 = 78;

#[derive(Debug, Serialize)]
struct DryRunPlan {
    workspace: String,
    workspace_source: DryRunWorkspaceSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_config_path: Option<String>,
    tag_path_pairs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    archive_entries: Vec<DryRunArchiveEntry>,
    env_vars: BTreeMap<String, String>,
    command: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<DryRunProxyPlan>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    tag_path_pair: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DryRunArchiveEntryRequestSource {
    Profile,
    Entry,
    CommandInferred,
    Manual,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DryRunArchiveResolutionSource {
    RepoConfig,
    BuiltIn,
    Manual,
}

#[derive(Debug, Clone, Serialize)]
struct DryRunProxyPlan {
    tag: String,
    host: String,
    endpoint_host: String,
    port: u16,
    read_only: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    metadata_hints: BTreeMap<String, String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    profiles: Vec<String>,
    entries: Vec<String>,
    verbose: bool,
    require_server_signature: bool,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: Vec<String>,
    recipient: Option<String>,
    identity: Option<String>,
    proxy: Option<String>,
    metadata_hints: Vec<String>,
    host: String,
    endpoint_host: Option<String>,
    port: u16,
    read_only: bool,
    save_on_failure: bool,
    skip_restore: bool,
    skip_save: bool,
    fail_on_cache_error: bool,
    fail_on_cache_miss: bool,
    dry_run: bool,
    json_output: bool,
    command: Vec<String>,
) -> Result<()> {
    if json_output && !dry_run {
        anyhow::bail!("--json is only supported with --dry-run for `boringcache run`.");
    }

    let has_manual_tags = !tag_path_pairs.is_empty();
    let has_planned_entries = !profiles.is_empty() || !entries.is_empty();

    if has_manual_tags && has_planned_entries {
        anyhow::bail!("Do not combine manual TAG_PATH_PAIRS with --entry or --profile.");
    }

    let infer_entries = !has_manual_tags && !has_planned_entries;
    let current_dir = std::env::current_dir().context("Failed to determine current directory")?;
    let resolved_plan = project_config::resolve_run_plan(
        &current_dir,
        &profiles,
        &entries,
        if infer_entries {
            command.as_slice()
        } else {
            &[]
        },
    )?;
    let project_config::ResolvedRunPlan {
        workspace: project_workspace,
        repo_config_path,
        tag_path_pairs: planned_pairs,
        env_vars,
        archive_entries: planned_archive_entries,
    } = resolved_plan;
    let explicit_workspace = workspace
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let workspace = utils::get_workspace_name_with_fallback(workspace, project_workspace.clone())?;
    let workspace_source = if explicit_workspace.is_some() {
        DryRunWorkspaceSource::Explicit
    } else if project_workspace.is_some() {
        DryRunWorkspaceSource::RepoConfig
    } else {
        DryRunWorkspaceSource::ConfiguredDefault
    };
    let tag_path_pairs = if has_manual_tags {
        tag_path_pairs
    } else {
        planned_pairs
    };
    let archive_entries = if has_manual_tags {
        build_manual_archive_entries(&tag_path_pairs)?
    } else {
        planned_archive_entries
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
                path: Some(entry.path),
                tag_path_pair: entry.tag_path_pair,
            })
            .collect()
    };
    let archive_enabled = !tag_path_pairs.is_empty();
    let proxy_enabled = proxy.is_some();
    let proxy_metadata_hints = serve::resolve_proxy_metadata_hints(&metadata_hints)?;
    let advertised_endpoint_host = endpoint_host
        .clone()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if host == "0.0.0.0" {
                "127.0.0.1".to_string()
            } else {
                host.clone()
            }
        });
    let effective_proxy_read_only = proxy_enabled && serve::effective_proxy_read_only(read_only);
    let effective_skip_save = skip_save || effective_proxy_read_only;

    if !archive_enabled && !proxy_enabled {
        anyhow::bail!(
            "No cache entries resolved. Provide manual TAG_PATHS, use --entry or --profile, run an inferrable command, or pass --proxy <TAG>."
        );
    }

    if archive_enabled {
        validate_archive_pairs(&tag_path_pairs, skip_restore, skip_save)?;
    }

    if dry_run {
        if json_output {
            let proxy_plan = proxy.as_ref().map(|tag| DryRunProxyPlan {
                tag: tag.to_string(),
                host: host.clone(),
                endpoint_host: advertised_endpoint_host.clone(),
                port,
                read_only: effective_proxy_read_only,
                metadata_hints: proxy_metadata_hints.clone(),
            });
            let plan = DryRunPlan {
                workspace: workspace.clone(),
                workspace_source,
                repo_config_path: repo_config_path.map(|path| path.display().to_string()),
                tag_path_pairs: tag_path_pairs.clone(),
                archive_entries: archive_entries.clone(),
                env_vars: env_vars.clone(),
                command: command.clone(),
                proxy: proxy_plan,
            };
            print_dry_run_json(plan)?;
        } else {
            print_dry_run(
                &workspace,
                &tag_path_pairs,
                &env_vars,
                no_platform,
                no_git,
                force,
                &exclude,
                recipient.as_deref(),
                identity.as_deref(),
                proxy.as_deref(),
                &proxy_metadata_hints,
                &host,
                endpoint_host.as_deref(),
                port,
                effective_proxy_read_only,
                save_on_failure,
                skip_restore,
                effective_skip_save,
                fail_on_cache_error,
                fail_on_cache_miss,
                &command,
            );
        }
        return Ok(());
    }

    if Config::load_for_auth_purpose(AuthPurpose::Restore).is_err() {
        ui::info("[boringcache] No token found — running command without caching");
        let child_outcome =
            proxy_exec::spawn_command(&command, &env_vars, None, inject_proxy_env).await?;
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

    if archive_enabled && !skip_restore {
        let restore_result = restore::execute_batch_restore(
            Some(workspace.clone()),
            tag_path_pairs.clone(),
            verbose,
            no_platform,
            no_git,
            fail_on_cache_miss,
            false,
            identity.clone(),
            fail_on_cache_error,
            require_server_signature,
        )
        .await;

        if let Err(error) = restore_result {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
    }

    let mut proxy_handle: Option<serve::ProxyServerHandle> = None;
    let mut proxy_context: Option<proxy_exec::ProxyContext> = None;

    if effective_proxy_read_only && !read_only && proxy_enabled {
        ui::info("[boringcache] No save-capable token found — starting proxy in read-only mode");
    }

    if let Some(proxy_tag) = proxy {
        let handle = serve::start_proxy_background(
            workspace.clone(),
            proxy_tag,
            host,
            port,
            no_platform,
            no_git,
            endpoint_host,
            proxy_metadata_hints.clone(),
            fail_on_cache_error,
            effective_proxy_read_only,
        )
        .await
        .map_err(|error| ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)))?;

        let cache_ref = handle.cache_ref();
        proxy_context = Some(proxy_exec::ProxyContext {
            endpoint_host: handle.endpoint_host().to_string(),
            port: handle.port(),
            cache_ref,
        });
        proxy_handle = Some(handle);
    }

    let child_outcome = proxy_exec::spawn_command(
        &command,
        &env_vars,
        proxy_context.as_ref(),
        inject_proxy_env,
    )
    .await;

    let child_outcome = match child_outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, false).await?;
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
                    tag_path_pairs,
                    verbose,
                    no_platform,
                    no_git,
                    force,
                    exclude,
                    recipient,
                    fail_on_cache_error,
                )
                .await;

                if let Err(error) = save_result
                    && fail_on_cache_error
                    && command_succeeded
                {
                    shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, false).await?;
                    return Err(
                        ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into(),
                    );
                }
            }

            shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, command_succeeded)
                .await?;

            if command_exit_code == 0 {
                Ok(())
            } else {
                Err(ExitCodeError::silent(command_exit_code).into())
            }
        }
    }
}

fn validate_archive_pairs(
    tag_path_pairs: &[String],
    skip_restore: bool,
    skip_save: bool,
) -> Result<()> {
    if tag_path_pairs.is_empty() {
        anyhow::bail!("At least one tag:path pair is required");
    }

    if !skip_save {
        for pair in tag_path_pairs {
            utils::parse_save_format(pair).map_err(anyhow::Error::from)?;
        }
        return Ok(());
    }

    if !skip_restore {
        for pair in tag_path_pairs {
            utils::parse_restore_format(pair).map_err(anyhow::Error::from)?;
        }
    }

    Ok(())
}

fn inject_proxy_env(command: &mut tokio::process::Command, context: &proxy_exec::ProxyContext) {
    let endpoint = context.endpoint();
    command.env("NX_SELF_HOSTED_REMOTE_CACHE_SERVER", &endpoint);
    command.env(
        "NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN",
        proxy_exec::PROXY_AUTH_TOKEN,
    );
    command.env("TURBO_API", &endpoint);
    command.env("TURBO_TOKEN", proxy_exec::PROXY_AUTH_TOKEN);
    command.env("TURBO_TEAM", proxy_exec::PROXY_AUTH_TOKEN);
    command.env(
        "GOCACHEPROG",
        format!("boringcache go-cacheprog --endpoint {}", endpoint),
    );
    command.env("RUSTC_WRAPPER", "sccache");
    command.env("SCCACHE_WEBDAV_ENDPOINT", format!("{endpoint}/"));
    command.env("BORINGCACHE_PROXY_PORT", context.port.to_string());
    command.env("BORINGCACHE_CACHE_REF", &context.cache_ref);
}

async fn shutdown_proxy_handle(
    proxy_handle: Option<serve::ProxyServerHandle>,
    fail_on_cache_error: bool,
    allow_override: bool,
) -> Result<()> {
    let Some(proxy_handle) = proxy_handle else {
        return Ok(());
    };

    if let Err(error) = proxy_handle.shutdown_and_flush().await {
        if fail_on_cache_error && allow_override {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
        ui::warn(&format!("Proxy shutdown warning: {:#}", error));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_dry_run(
    workspace: &str,
    tag_path_pairs: &[String],
    env_vars: &BTreeMap<String, String>,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: &[String],
    recipient: Option<&str>,
    identity: Option<&str>,
    proxy: Option<&str>,
    proxy_metadata_hints: &BTreeMap<String, String>,
    host: &str,
    endpoint_host: Option<&str>,
    port: u16,
    read_only: bool,
    save_on_failure: bool,
    skip_restore: bool,
    skip_save: bool,
    fail_on_cache_error: bool,
    fail_on_cache_miss: bool,
    command: &[String],
) {
    ui::info("[boringcache] Dry run:");

    if !tag_path_pairs.is_empty() && !skip_restore {
        let pairs = format!("\"{}\"", tag_path_pairs.join(","));
        let mut restore_parts = vec![
            "boringcache".to_string(),
            "restore".to_string(),
            workspace.to_string(),
            pairs.clone(),
        ];
        if no_platform {
            restore_parts.push("--no-platform".to_string());
        }
        if no_git {
            restore_parts.push("--no-git".to_string());
        }
        if fail_on_cache_miss {
            restore_parts.push("--fail-on-cache-miss".to_string());
        }
        if fail_on_cache_error {
            restore_parts.push("--fail-on-cache-error".to_string());
        }
        if let Some(identity) = identity {
            restore_parts.push("--identity".to_string());
            restore_parts.push(identity.to_string());
        }
        ui::info(&format!("[boringcache]   {}", restore_parts.join(" ")));
    }

    if let Some(proxy_tag) = proxy {
        let mut proxy_parts = vec![
            "boringcache".to_string(),
            "serve".to_string(),
            workspace.to_string(),
            proxy_tag.to_string(),
            "--host".to_string(),
            host.to_string(),
            "--port".to_string(),
            port.to_string(),
        ];
        if let Some(endpoint_host) = endpoint_host {
            proxy_parts.push("--endpoint-host".to_string());
            proxy_parts.push(endpoint_host.to_string());
        }
        if no_platform {
            proxy_parts.push("--no-platform".to_string());
        }
        if no_git {
            proxy_parts.push("--no-git".to_string());
        }
        if read_only {
            proxy_parts.push("--read-only".to_string());
        }
        if fail_on_cache_error {
            proxy_parts.push("--fail-on-cache-error".to_string());
        }
        for (key, value) in proxy_metadata_hints {
            proxy_parts.push("--metadata-hint".to_string());
            proxy_parts.push(format!("{key}={value}"));
        }
        ui::info(&format!("[boringcache]   {}", proxy_parts.join(" ")));
    }

    for (key, value) in env_vars {
        ui::info(&format!("[boringcache]   env {key}={value}"));
    }

    if !command.is_empty() {
        ui::info(&format!("[boringcache]   {}", command.join(" ")));
    }

    if !tag_path_pairs.is_empty() && !skip_save {
        let pairs = format!("\"{}\"", tag_path_pairs.join(","));
        let mut save_parts = vec![
            "boringcache".to_string(),
            "save".to_string(),
            workspace.to_string(),
            pairs,
        ];
        if no_platform {
            save_parts.push("--no-platform".to_string());
        }
        if no_git {
            save_parts.push("--no-git".to_string());
        }
        if force {
            save_parts.push("--force".to_string());
        }
        if fail_on_cache_error {
            save_parts.push("--fail-on-cache-error".to_string());
        }
        if let Some(recipient) = recipient {
            save_parts.push("--recipient".to_string());
            save_parts.push(recipient.to_string());
        }
        for pattern in exclude {
            save_parts.push("--exclude".to_string());
            save_parts.push(pattern.clone());
        }
        ui::info(&format!("[boringcache]   {}", save_parts.join(" ")));
    } else if read_only && !tag_path_pairs.is_empty() {
        ui::info("[boringcache]   # save phase skipped in read-only mode");
    }

    if save_on_failure && !tag_path_pairs.is_empty() {
        ui::info("[boringcache]   # save phase enabled for non-zero command exits");
    }
}

fn print_dry_run_json(plan: DryRunPlan) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

fn build_manual_archive_entries(tag_path_pairs: &[String]) -> Result<Vec<DryRunArchiveEntry>> {
    tag_path_pairs
        .iter()
        .map(|pair| {
            let parsed = utils::parse_restore_format(pair).map_err(anyhow::Error::from)?;
            Ok(DryRunArchiveEntry {
                requested: parsed.tag.clone(),
                request_source: DryRunArchiveEntryRequestSource::Manual,
                profile: None,
                resolution_source: DryRunArchiveResolutionSource::Manual,
                tag: parsed.tag,
                path: parsed.path,
                tag_path_pair: pair.clone(),
            })
        })
        .collect()
}

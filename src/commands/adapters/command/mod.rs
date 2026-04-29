use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::cli::AdapterArgs;
use crate::commands::{cache_registry, restore, save};
use crate::config::{AuthPurpose, Config};
use crate::exit_code::ExitCodeError;
use crate::project_config;
use crate::ui;
use crate::{command_support, proxy};

mod bazel;
mod docker;
mod go;
mod gradle;
mod maven;
mod node_package_manager;
mod nx;
mod sccache;
mod setup_plan;
mod turbo;

const EXIT_CONFIG: i32 = 78;

type ProxyEnvSet = BTreeMap<String, String>;
type InjectProxyEnvFn = fn(&mut ProxyEnvSet, &proxy::ProxyContext, &AdapterCommandOptions);
type PrepareCommandFn =
    fn(&[String], Option<&proxy::ProxyContext>, &AdapterCommandOptions) -> Result<Vec<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    Buildkit,
}

struct AdapterRunner {
    name: &'static str,
    inject_proxy_env: InjectProxyEnvFn,
    prepare_command: PrepareCommandFn,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProxyEnvPlan {
    set: ProxyEnvSet,
}

#[derive(Debug, Clone)]
struct AdapterCommandOptions {
    cache_ref_tag: String,
    cache_mode: String,
    read_only: bool,
    docker_oci_cache: Option<docker::OciCachePlan>,
    sccache_key_prefix: Option<String>,
    gradle_home: Option<String>,
    node_package_manager_env: ProxyEnvSet,
    skip_actions: Vec<String>,
}

impl AdapterRunner {
    fn proxy_env_plan(
        &self,
        context: &proxy::ProxyContext,
        options: &AdapterCommandOptions,
    ) -> ProxyEnvPlan {
        let mut set = BTreeMap::new();
        set.insert(
            "BORINGCACHE_PROXY_PORT".to_string(),
            context.port.to_string(),
        );
        set.insert(
            "BORINGCACHE_CACHE_REF".to_string(),
            context.cache_ref.clone(),
        );
        (self.inject_proxy_env)(&mut set, context, options);
        ProxyEnvPlan { set }
    }
}

impl AdapterKind {
    pub fn toml_key(self) -> &'static str {
        runner_for(self).name
    }

    fn display_name(self) -> &'static str {
        runner_for(self).name
    }

    fn telemetry_tool(self) -> &'static str {
        match self {
            Self::Turbo => "turborepo",
            Self::Nx => "nx",
            Self::Bazel => "bazel",
            Self::Gradle => "gradle",
            Self::Maven => "maven",
            Self::Sccache => "sccache",
            Self::Go => "gocache",
            Self::Docker => "oci",
            Self::Buildkit => "oci",
        }
    }

    fn proxy_env_plan(
        self,
        context: &proxy::ProxyContext,
        options: &AdapterCommandOptions,
    ) -> ProxyEnvPlan {
        runner_for(self).proxy_env_plan(context, options)
    }

    fn inject_proxy_env(
        self,
        command: &mut tokio::process::Command,
        context: &proxy::ProxyContext,
        options: &AdapterCommandOptions,
    ) {
        command.envs(self.proxy_env_plan(context, options).set);
    }

    fn prepare_command(
        self,
        command: &[String],
        proxy_context: Option<&proxy::ProxyContext>,
        options: &AdapterCommandOptions,
    ) -> Result<Vec<String>> {
        (runner_for(self).prepare_command)(command, proxy_context, options)
    }
}

fn runner_for(kind: AdapterKind) -> &'static AdapterRunner {
    match kind {
        AdapterKind::Turbo => &turbo::RUNNER,
        AdapterKind::Nx => &nx::RUNNER,
        AdapterKind::Bazel => &bazel::RUNNER,
        AdapterKind::Gradle => &gradle::RUNNER,
        AdapterKind::Maven => &maven::RUNNER,
        AdapterKind::Sccache => &sccache::RUNNER,
        AdapterKind::Go => &go::RUNNER,
        AdapterKind::Docker => &docker::RUNNER,
        AdapterKind::Buildkit => &docker::BUILDKIT_RUNNER,
    }
}

fn no_extra_proxy_env(_: &mut ProxyEnvSet, _: &proxy::ProxyContext, _: &AdapterCommandOptions) {}

fn passthrough_command(
    command: &[String],
    _: Option<&proxy::ProxyContext>,
    _: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    Ok(command.to_vec())
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
    #[serde(skip_serializing_if = "setup_plan::AdapterSetupPlan::is_empty")]
    setup: setup_plan::AdapterSetupPlan,
    proxy: DryRunProxyPlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    oci_cache: Option<docker::OciCachePlan>,
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
    no_platform: bool,
    no_git: bool,
    read_only: bool,
    startup_mode: String,
    oci_hydration: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    oci_prefetch_refs: Vec<String>,
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
    let workspace = command_support::get_workspace_name_with_fallback(
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

    let raw_tag = resolve_adapter_tag(kind, args.tag.as_deref(), adapter_config.tag.as_deref())?;

    let command = if !args.command.is_empty() {
        args.command.clone()
    } else if let Some(command) = adapter_config.command.as_ref() {
        command.argv()?
    } else {
        Vec::new()
    };
    if command.is_empty() && !args.dry_run {
        anyhow::bail!(
            "Missing command. Pass one after -- or configure [adapters.{}].command in .boringcache.toml.",
            kind.toml_key()
        );
    }

    let no_platform = adapter_config.no_platform || args.no_platform;
    let no_git = adapter_config.no_git || args.no_git;
    let configured_read_only = adapter_config.read_only || args.read_only;
    let bind_host = project_config::prefer_cli_scalar(
        trim_non_empty(adapter_config.host.as_deref()).map(ToOwned::to_owned),
        trim_non_empty(args.host.as_deref()).map(ToOwned::to_owned),
    )
    .unwrap_or_else(|| "127.0.0.1".to_string());
    let endpoint_host_override = project_config::prefer_cli_scalar(
        trim_non_empty(adapter_config.endpoint_host.as_deref()).map(ToOwned::to_owned),
        trim_non_empty(args.endpoint_host.as_deref()).map(ToOwned::to_owned),
    );
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
    let metadata_hint_args = merge_metadata_hints(
        loaded_config
            .as_ref()
            .map(|loaded| loaded.config.proxy.metadata_hints.as_slice())
            .unwrap_or(&[]),
        &adapter_config.metadata_hints,
        &args.metadata_hint,
    );
    let mut oci_prefetch_refs = cache_registry::resolve_oci_prefetch_refs(&args.oci_prefetch_ref)?;
    let oci_hydration_policy = cache_registry::resolve_oci_hydration_policy(&args.oci_hydration)?;
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
    let effective_read_only = cache_registry::effective_proxy_read_only(configured_read_only);
    let docker_read_only_on_demand =
        matches!(kind, AdapterKind::Docker | AdapterKind::Buildkit) && effective_read_only;
    let startup_warm = !(args.on_demand || docker_read_only_on_demand);
    let mut proxy_metadata_hints =
        cache_registry::resolve_proxy_metadata_hints(&metadata_hint_args)?;
    cache_registry::inject_default_proxy_metadata_hints(&mut proxy_metadata_hints);
    if kind != AdapterKind::Docker {
        cache_registry::insert_replayable_proxy_metadata_hint(
            &mut proxy_metadata_hints,
            "tool",
            kind.telemetry_tool(),
        );
    }
    let mut generated_proxy_metadata_hints = Vec::new();
    let effective_skip_save = skip_save || effective_read_only;
    let docker_cache_mode = project_config::prefer_cli_scalar(
        adapter_config.cache_mode.clone(),
        args.cache_mode.clone(),
    )
    .unwrap_or_else(|| "max".to_string());
    docker::validate_cache_mode(&docker_cache_mode)?;
    let docker_plan = if matches!(kind, AdapterKind::Docker | AdapterKind::Buildkit) {
        let cache_from_ref_tags = project_config::prefer_cli_list(
            &adapter_config.cache_from_ref_tags,
            &args.cache_from_ref_tag,
            |value| value.trim().to_string(),
        );
        let cache_promote_ref_tags = project_config::prefer_cli_list(
            &adapter_config.cache_promote_ref_tags,
            &args.cache_promote_ref_tag,
            |value| value.trim().to_string(),
        );
        let run_context = crate::ci_detection::detect_ci_context()
            .run_context()
            .cloned();
        let plan = docker::resolve_docker_plan(docker::ResolveDockerPlanInput {
            raw_tag: &raw_tag,
            explicit_cache_ref_tag: project_config::prefer_cli_scalar(
                adapter_config.cache_ref_tag.as_deref(),
                args.cache_ref_tag.as_deref(),
            ),
            explicit_cache_run_ref_tag: project_config::prefer_cli_scalar(
                adapter_config.cache_run_ref_tag.as_deref(),
                args.cache_run_ref_tag.as_deref(),
            ),
            explicit_cache_from_ref_tags: &cache_from_ref_tags,
            explicit_cache_promote_ref_tags: &cache_promote_ref_tags,
            endpoint_host: &advertised_endpoint_host,
            port,
            cache_mode: &docker_cache_mode,
            read_only: effective_read_only,
            run_context,
        })?;
        Some(plan)
    } else {
        None
    };
    if let Some(plan) = &docker_plan {
        generated_proxy_metadata_hints
            .push(("docker_cache_ref_tag", plan.oci_cache.ref_tag.clone()));
        if let Some(run_ref) = plan.oci_cache.immutable_run_ref_tag.as_deref() {
            generated_proxy_metadata_hints.push(("docker_immutable_run_ref", run_ref.to_string()));
        }
        if !plan.oci_cache.promotion_ref_tags.is_empty() {
            generated_proxy_metadata_hints.push((
                "docker_alias_promotion_refs",
                plan.oci_cache.promotion_ref_tags.join("/"),
            ));
        }
        if let Some(run_metadata) = plan.oci_cache.run_metadata.as_ref() {
            generated_proxy_metadata_hints.push(("ci_provider", run_metadata.provider.clone()));
            if let Some(run_started_at) = run_metadata.run_started_at.as_deref() {
                generated_proxy_metadata_hints
                    .push(("ci_run_started_at", run_started_at.to_string()));
            }
            generated_proxy_metadata_hints.push((
                "ci_ref_type",
                match run_metadata.source_ref_type {
                    crate::ci_detection::CiSourceRefType::Branch => "branch",
                    crate::ci_detection::CiSourceRefType::Tag => "tag",
                    crate::ci_detection::CiSourceRefType::PullRequest => "pull-request",
                    crate::ci_detection::CiSourceRefType::Other => "other",
                }
                .to_string(),
            ));
            if let Some(pull_request_number) = run_metadata.pull_request_number {
                generated_proxy_metadata_hints
                    .push(("ci_pr_number", pull_request_number.to_string()));
            }
            if let Some(attempt) = run_metadata.run_attempt.as_deref() {
                generated_proxy_metadata_hints.push(("ci_run_attempt", attempt.to_string()));
            }
            if let Some(source_ref_name) = run_metadata.source_ref_name.as_deref() {
                generated_proxy_metadata_hints.push(("ci_ref_name", source_ref_name.to_string()));
            }
            if let Some(commit_sha) = run_metadata.commit_sha.as_deref() {
                generated_proxy_metadata_hints.push(("ci_commit_sha", commit_sha.to_string()));
            }
            if let Some(default_branch) = run_metadata.default_branch.as_deref() {
                generated_proxy_metadata_hints
                    .push(("ci_default_branch", default_branch.to_string()));
            }
        }
        for (key, value) in generated_proxy_metadata_hints.drain(..) {
            cache_registry::insert_replayable_proxy_metadata_hint(
                &mut proxy_metadata_hints,
                key,
                &value,
            );
        }
    }
    if startup_warm && let Some(plan) = &docker_plan {
        for ref_tag in plan
            .oci_cache
            .cache_from_ref_tags
            .iter()
            .map(|tag| ("cache".to_string(), tag.clone()))
        {
            if !oci_prefetch_refs
                .iter()
                .any(|existing| existing == &ref_tag)
            {
                oci_prefetch_refs.push(ref_tag);
            }
        }
    }
    let oci_prefetch_ref_specs = oci_prefetch_refs
        .iter()
        .map(|(name, reference)| format!("{name}@{reference}"))
        .collect::<Vec<_>>();
    let tag = raw_tag.clone();
    let docker_cache_ref_tag = docker_plan
        .as_ref()
        .map(|plan| plan.oci_cache.ref_tag.clone())
        .or_else(|| {
            project_config::prefer_cli_scalar(
                adapter_config.cache_ref_tag.clone(),
                args.cache_ref_tag.clone(),
            )
        })
        .unwrap_or_else(|| "buildcache".to_string());
    let gradle_home = args
        .gradle_home
        .as_deref()
        .map(|value| setup_plan::resolve_setup_path_string(value, &current_dir))
        .transpose()?;
    let command_options = AdapterCommandOptions {
        cache_ref_tag: docker_cache_ref_tag,
        cache_mode: docker_cache_mode,
        read_only: effective_read_only,
        docker_oci_cache: docker_plan.as_ref().map(|plan| plan.oci_cache.clone()),
        sccache_key_prefix: trim_non_empty(adapter_config.sccache_key_prefix.as_deref())
            .map(ToOwned::to_owned),
        gradle_home,
        node_package_manager_env: if matches!(kind, AdapterKind::Turbo | AdapterKind::Nx) {
            node_package_manager::cache_env_for_project(&current_dir)
        } else {
            BTreeMap::new()
        },
        skip_actions: adapter_skip_actions(kind, loaded_config.as_ref())?,
    };

    let preview_context = proxy::ProxyContext {
        endpoint_host: advertised_endpoint_host.clone(),
        port,
        cache_ref: docker_plan
            .as_ref()
            .map(|plan| plan.oci_cache.registry_ref.clone())
            .map(Ok)
            .unwrap_or_else(|| {
                cache_registry::planned_cache_ref(
                    &tag,
                    &advertised_endpoint_host,
                    port,
                    no_platform,
                    no_git,
                )
            })?,
    };
    let preview_command = proxy::substitute_proxy_placeholders(
        &kind.prepare_command(&command, Some(&preview_context), &command_options)?,
        &preview_context,
    );
    let mut preview_env_vars = resolved_plan.env_vars.clone();
    preview_env_vars.extend(kind.proxy_env_plan(&preview_context, &command_options).set);

    if args.dry_run {
        let preview_setup = setup_plan::adapter_setup_plan(
            kind,
            &args,
            &current_dir,
            &preview_context,
            &command_options,
        )?;
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
            setup: preview_setup,
            proxy: DryRunProxyPlan {
                host: bind_host,
                endpoint_host: advertised_endpoint_host,
                port,
                no_platform,
                no_git,
                read_only: effective_read_only,
                startup_mode: cache_registry::proxy_startup_mode(startup_warm).to_string(),
                oci_hydration: oci_hydration_policy.as_str().to_string(),
                oci_prefetch_refs: oci_prefetch_ref_specs,
                metadata_hints: proxy_metadata_hints,
            },
            oci_cache: docker_plan.map(|plan| plan.oci_cache),
        };

        if args.json {
            crate::json_output::print(&plan)?;
        } else {
            print_dry_run(&plan, effective_skip_save, skip_restore, save_on_failure);
        }
        return Ok(());
    }

    let has_restore_auth = Config::load_for_auth_purpose(AuthPurpose::Restore).is_ok();
    if !has_restore_auth {
        ui::info("[boringcache] No token found — running command without caching");
        let child_outcome =
            proxy::spawn_command(&command, &resolved_plan.env_vars, None, |_, _| {}).await?;
        return match child_outcome {
            proxy::ChildOutcome::Exited(status) => {
                run_post_command_diagnostics(kind).await;
                let code = proxy::status_exit_code(&status);
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
            false,
            fail_on_cache_error,
            require_server_signature,
        )
        .await;

        if let Err(error) = restore_result {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
    }

    let proxy_handle = cache_registry::start_proxy_background(
        workspace.clone(),
        tag,
        bind_host,
        port,
        no_platform,
        no_git,
        oci_prefetch_refs,
        oci_hydration_policy,
        endpoint_host_override,
        proxy_metadata_hints,
        startup_warm,
        fail_on_cache_error,
        effective_read_only,
        docker_plan
            .as_ref()
            .map(|plan| plan.oci_cache.promotion_ref_tags.clone())
            .unwrap_or_default(),
    )
    .await
    .map_err(|error| ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)))?;

    let proxy_context = proxy::ProxyContext {
        endpoint_host: proxy_handle.endpoint_host().to_string(),
        port: proxy_handle.port(),
        cache_ref: proxy_handle.cache_ref(),
    };

    let runtime_setup = if setup_plan::applies_during_runtime(kind) {
        let setup = match setup_plan::adapter_setup_plan(
            kind,
            &args,
            &current_dir,
            &proxy_context,
            &command_options,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                shutdown_proxy_handle(proxy_handle, fail_on_cache_error, false).await?;
                return Err(error);
            }
        };
        if let Err(error) = setup_plan::apply_adapter_setup_plan(&setup) {
            shutdown_proxy_handle(proxy_handle, fail_on_cache_error, false).await?;
            return Err(error);
        }
        setup
    } else {
        setup_plan::AdapterSetupPlan::default()
    };

    let command_to_run =
        match kind.prepare_command(&command, Some(&proxy_context), &command_options) {
            Ok(command) => command,
            Err(error) => {
                shutdown_proxy_handle(proxy_handle, fail_on_cache_error, false).await?;
                return Err(error);
            }
        };
    let mut command_env_vars = resolved_plan.env_vars.clone();
    command_env_vars.extend(runtime_setup.env_vars.clone());

    let child_outcome = proxy::spawn_command(
        &command_to_run,
        &command_env_vars,
        Some(&proxy_context),
        |process, context| kind.inject_proxy_env(process, context, &command_options),
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
        proxy::ChildOutcome::Exited(status) => {
            let command_succeeded = status.success();
            let command_exit_code = proxy::status_exit_code(&status);

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

            run_post_command_diagnostics(kind).await;
            shutdown_proxy_handle(proxy_handle, fail_on_cache_error, command_succeeded).await?;

            if command_exit_code == 0 {
                Ok(())
            } else {
                Err(ExitCodeError::silent(command_exit_code).into())
            }
        }
    }
}

async fn run_post_command_diagnostics(kind: AdapterKind) {
    if kind == AdapterKind::Sccache {
        sccache::print_stats_summary().await;
    }
}

fn trim_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn adapter_skip_actions(
    kind: AdapterKind,
    loaded_config: Option<&project_config::LoadedRepoConfig>,
) -> Result<Vec<String>> {
    let Some(loaded_config) = loaded_config else {
        return Ok(Vec::new());
    };
    let tool = kind.telemetry_tool();
    Ok(
        crate::serve::state::proxy_skip_rules_from_config(&loaded_config.config.skip)?
            .into_iter()
            .filter(|rule| rule.tool == tool)
            .map(|rule| rule.action)
            .collect(),
    )
}

fn resolve_adapter_tag(
    kind: AdapterKind,
    cli_tag: Option<&str>,
    configured_tag: Option<&str>,
) -> Result<String> {
    if let Some(tag) = project_config::prefer_cli_scalar(
        trim_non_empty(configured_tag).map(ToOwned::to_owned),
        trim_non_empty(cli_tag).map(ToOwned::to_owned),
    ) {
        return Ok(tag);
    }

    if let Some(repo_name) = trim_non_empty(std::env::var("GITHUB_REPOSITORY").ok().as_deref())
        .map(|value| value.rsplit('/').next().unwrap_or(value).trim())
        .filter(|value| !value.is_empty())
    {
        return Ok(repo_name.to_string());
    }

    Ok(kind.display_name().to_string())
}

fn merge_entries(configured: &[String], cli: &[String]) -> Vec<String> {
    project_config::prefer_cli_list(configured, cli, project_config::canonical_entry_id)
}

fn merge_profiles(configured: &[String], cli: &[String]) -> Vec<String> {
    project_config::prefer_cli_list(configured, cli, project_config::normalize_profile_name)
}

fn merge_metadata_hints(
    configured_proxy: &[String],
    configured_adapter: &[String],
    cli: &[String],
) -> Vec<String> {
    let mut merged = Vec::new();
    merged.extend(configured_proxy.iter().cloned());
    merged.extend(configured_adapter.iter().cloned());
    merged.extend(cli.iter().cloned());
    merged
}

async fn shutdown_proxy_handle(
    proxy_handle: cache_registry::ProxyServerHandle,
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
        "[boringcache]   proxy {}:{} (bind {}, mode: {}, read-only: {})",
        plan.proxy.endpoint_host,
        plan.proxy.port,
        plan.proxy.host,
        plan.proxy.startup_mode,
        if plan.proxy.read_only { "yes" } else { "no" }
    ));

    for (key, value) in &plan.proxy.metadata_hints {
        ui::info(&format!("[boringcache]   hint {key}={value}"));
    }

    for oci_prefetch_ref in &plan.proxy.oci_prefetch_refs {
        ui::info(&format!("[boringcache]   oci-prefetch {oci_prefetch_ref}"));
    }
    if plan.proxy.oci_hydration != crate::serve::OciHydrationPolicy::default().as_str() {
        ui::info(&format!(
            "[boringcache]   oci-hydration {}",
            plan.proxy.oci_hydration
        ));
    }

    for entry in &plan.archive_entries {
        if !skip_restore {
            ui::info(&format!("[boringcache]   restore {}", entry.tag_path_pair));
        }
    }

    for (key, value) in &plan.env_vars {
        ui::info(&format!("[boringcache]   env {key}={value}"));
    }

    for (key, value) in &plan.setup.env_vars {
        ui::info(&format!("[boringcache]   setup env {key}={value}"));
    }
    for directory in &plan.setup.directories {
        ui::info(&format!("[boringcache]   setup dir {directory}"));
    }
    for file in &plan.setup.files {
        ui::info(&format!(
            "[boringcache]   setup file {:?} {}",
            file.mode, file.path
        ));
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
    fn merge_entries_prefers_cli_list_when_present() {
        let configured = vec!["bundler".to_string(), "pnpm-store".to_string()];
        let cli = vec!["node-modules".to_string(), "bundler".to_string()];

        assert_eq!(
            merge_entries(&configured, &cli),
            vec!["node_modules".to_string(), "bundler".to_string()]
        );
        assert_eq!(
            merge_entries(&configured, &[]),
            vec!["bundler".to_string(), "pnpm-store".to_string()]
        );
    }

    #[test]
    fn merge_profiles_prefers_cli_list_when_present() {
        let configured = vec!["bundle-install".to_string(), "warm".to_string()];
        let cli = vec!["release".to_string(), "bundle_install".to_string()];

        assert_eq!(
            merge_profiles(&configured, &cli),
            vec!["release".to_string(), "bundle-install".to_string()]
        );
        assert_eq!(
            merge_profiles(&configured, &[]),
            vec!["bundle-install".to_string(), "warm".to_string()]
        );
    }

    #[test]
    fn merge_metadata_hints_keeps_configured_order_and_appends_cli_values() {
        let configured_proxy = vec!["project=web".to_string()];
        let configured_adapter = vec!["phase=warm".to_string(), "tool=turbo".to_string()];
        let cli = vec!["phase=ready".to_string(), "lane=ci".to_string()];

        assert_eq!(
            merge_metadata_hints(&configured_proxy, &configured_adapter, &cli),
            vec![
                "project=web".to_string(),
                "phase=warm".to_string(),
                "tool=turbo".to_string(),
                "phase=ready".to_string(),
                "lane=ci".to_string()
            ]
        );
    }

    #[test]
    fn adapter_telemetry_tools_match_rails_rollup_vocabulary() {
        let tools = [
            (AdapterKind::Turbo, "turborepo"),
            (AdapterKind::Nx, "nx"),
            (AdapterKind::Bazel, "bazel"),
            (AdapterKind::Gradle, "gradle"),
            (AdapterKind::Maven, "maven"),
            (AdapterKind::Sccache, "sccache"),
            (AdapterKind::Go, "gocache"),
            (AdapterKind::Docker, "oci"),
            (AdapterKind::Buildkit, "oci"),
        ];

        for (adapter, tool) in tools {
            assert_eq!(adapter.telemetry_tool(), tool);
        }
    }
}

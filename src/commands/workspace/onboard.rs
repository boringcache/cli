use crate::api::client::ApiClient;
use crate::api::models::CliConnectTokenScope;
use crate::api::models::optimize::{
    OptimizeChange, OptimizeFileRequest, OptimizeFileResult, OptimizeRequest, OptimizeResponse,
};
use crate::api::models::workspace::{
    WorkspaceProvisionParams, WorkspaceProvisionRequest, WorkspaceTokenPairCreateParams,
    WorkspaceTokenPairCreateRequest, WorkspaceTokenPairResponse,
};
use crate::config::{self, Config};
use crate::optimize::detect::{detect_ci_type, score_relevance};
use crate::optimize::transform::{
    TransformResult, deterministic_optimize, preserve_trailing_newline, validate_output,
};
use crate::optimize::{CiType, FileRelevance, MAX_FILES_PER_REQUEST};
use crate::types::Result;
use crate::ui;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug)]
struct ScannedFile {
    path: PathBuf,
    display_path: String,
    content: String,
    ci_type: CiType,
    relevance: FileRelevance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RiskLevel {
    Low,
    Review,
    High,
}

impl RiskLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Review => "review",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone)]
struct RiskReport {
    level: RiskLevel,
    summary: String,
    paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct SavingsEstimate {
    min_seconds: u32,
    max_seconds: u32,
    min_percent: u8,
    max_percent: u8,
    confidence: &'static str,
    baseline: &'static str,
}

#[derive(Debug, Clone)]
struct OptimizationAnalysis {
    risk: RiskReport,
    savings: SavingsEstimate,
}

#[derive(Debug, Clone)]
struct ProposedChange<'a> {
    file: &'a ScannedFile,
    content: String,
    analysis: OptimizationAnalysis,
}

#[derive(Debug, Clone)]
pub(crate) struct CliEmailAuthOptions {
    email: String,
    name: Option<String>,
    username: Option<String>,
}

impl CliEmailAuthOptions {
    pub(crate) fn from_inputs(
        email: Option<String>,
        name: Option<String>,
        username: Option<String>,
    ) -> Option<Self> {
        email.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(Self {
                    email: trimmed,
                    name: normalize_optional_input(name),
                    username: normalize_optional_input(username),
                })
            }
        })
    }
}

#[derive(Debug, Default, Serialize)]
struct OnboardAutomationReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<WorkspaceAutomationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_config: Option<RepoConfigAutomationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ci_tokens: Option<CiTokenAutomationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    github_secrets: Option<GithubSecretsAutomationReport>,
    optimize_results: Vec<OptimizeFileResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    next_steps: Vec<String>,
}

#[derive(Debug, Serialize)]
struct WorkspaceAutomationReport {
    slug: String,
    created: bool,
    provisioned: bool,
}

#[derive(Debug, Serialize)]
struct RepoConfigAutomationReport {
    path: String,
    workspace: String,
    wrote: bool,
    added_entries: usize,
    added_profiles: usize,
}

#[derive(Debug, Serialize)]
struct CiTokenAutomationReport {
    status: String,
    restore_token_id: String,
    save_token_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    restore_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    save_value: Option<String>,
}

#[derive(Debug, Serialize)]
struct GithubSecretsAutomationReport {
    repo: String,
    status: String,
    updated: Vec<String>,
}

#[derive(Debug, Clone)]
struct RepoWorkspaceConfigResult {
    path: PathBuf,
    workspace: String,
    wrote: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    path: Option<String>,
    workspace: Option<String>,
    create_workspace: bool,
    create_ci_tokens: bool,
    github_secrets: bool,
    github_repo: Option<String>,
    rotate_ci_tokens: bool,
    workspace_name: Option<String>,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
    auto_apply: bool,
    dry_run: bool,
    manual: bool,
    json_output: bool,
) -> Result<()> {
    let mut target_workspace = workspace
        .as_deref()
        .map(normalize_workspace_path)
        .transpose()?;
    let explicit_automation_requested = target_workspace.is_some()
        || create_workspace
        || create_ci_tokens
        || github_secrets
        || github_repo.is_some();
    let effective_create_ci_tokens = create_ci_tokens || github_secrets;
    let mut automation_report = OnboardAutomationReport::default();
    let interactive = !json_output && std::io::stdin().is_terminal();

    if interactive {
        let needs_auth = if optimize_auth_configured() {
            let client = ApiClient::new()?;
            let session_result = client.get_session_info().await;
            session_result.is_err()
        } else {
            true
        };

        if needs_auth {
            let cli_email_auth = CliEmailAuthOptions::from_inputs(email, name, username);

            ui::info("Welcome to BoringCache.");
            ui::blank_line();
            ui::info("Let's connect your account and set up caching for this project.");
            ui::info("Repo scanning and config changes stay local to this machine.");
            ui::info("Browser approval only grants this CLI workspace access.");
            ui::blank_line();

            let token = match run_cli_connect_onboarding(
                manual,
                cli_email_auth,
                CliConnectTokenScope::Workspace,
            )
            .await
            {
                Ok(token) => token,
                Err(err) => {
                    ui::warn(&format!("Interactive sign-in failed: {err}"));
                    if !prompt_yes_no("Paste a token manually instead? [Y/n] ", true)? {
                        return Err(err);
                    }
                    prompt_non_empty("BoringCache API token: ")?
                }
            };

            crate::commands::auth::execute_with_options(token.clone(), false).await?;
            ensure_default_workspace_after_onboarding(&token).await?;
            ui::blank_line();
        }
    }

    let interactive_workspace_selection = if interactive && target_workspace.is_none() {
        select_interactive_workspace_for_repo().await?
    } else {
        None
    };

    if let Some(selection) = &interactive_workspace_selection {
        target_workspace = Some(selection.workspace.clone());
    }

    let automation_requested = explicit_automation_requested || target_workspace.is_some();

    if let Some(workspace) = target_workspace.as_deref() {
        let should_provision_workspace = create_workspace
            || interactive_workspace_selection
                .as_ref()
                .is_some_and(|selection| selection.should_provision);

        if should_provision_workspace {
            let response = provision_workspace(workspace, workspace_name.as_deref()).await?;
            if !json_output {
                let action = if response.created {
                    "Created workspace"
                } else {
                    "Workspace already exists"
                };
                ui::info(&format!("{action}: {}", response.slug));
            }
            automation_report.workspace = Some(WorkspaceAutomationReport {
                slug: response.slug,
                created: response.created,
                provisioned: response.provisioned,
            });
        }

        if github_secrets {
            let repo = github_repo.clone().unwrap_or_else(|| workspace.to_string());
            let secret_report = ensure_github_split_secrets(
                workspace,
                &repo,
                rotate_ci_tokens,
                json_output,
                &mut automation_report,
            )
            .await?;
            automation_report.github_secrets = Some(secret_report);
        } else if effective_create_ci_tokens {
            let token_pair = create_ci_token_pair(workspace).await?;
            automation_report.ci_tokens = Some(ci_token_report(&token_pair, true));
        }

        if interactive && !dry_run {
            record_repo_workspace_config(workspace, &mut automation_report)?;
        }

        if interactive && !github_secrets && !dry_run {
            maybe_setup_github_secrets_interactively(
                workspace,
                github_repo.as_deref(),
                rotate_ci_tokens,
                json_output,
                &mut automation_report,
            )
            .await?;
        }
    }

    let files = if let Some(ref path) = path {
        scan_single_file(path)?
    } else {
        scan_project()?
    };

    if files.is_empty() {
        if auto_apply && let Some(workspace) = target_workspace.as_deref() {
            let config_result = ensure_repo_workspace_config(workspace)?;
            automation_report.repo_config = Some(RepoConfigAutomationReport {
                path: config_result.path.display().to_string(),
                workspace: config_result.workspace,
                wrote: config_result.wrote,
                added_entries: 0,
                added_profiles: 0,
            });
        }

        if json_output {
            if automation_requested {
                print_automation_report(&mut automation_report)?;
            } else {
                println!("{{\"results\":[]}}");
            }
        } else {
            ui::info("No CI/CD configuration files found.");
            ui::blank_line();

            let workspace = Config::load().ok().and_then(|c| c.default_workspace);

            if let Some(ref ws) = workspace {
                ui::info("You can use BoringCache locally:");
                ui::info(&format!(
                    "  boringcache run {} \"deps:node_modules\" -- npm ci",
                    ws
                ));
            } else {
                ui::info("You can use BoringCache locally:");
                ui::info("  boringcache run <workspace> \"deps:node_modules\" -- npm ci");
            }

            ui::blank_line();
            ui::info("Or add a CI config and run 'boringcache onboard' again.");
            print_repo_config_tip();
        }
        return Ok(());
    }

    if !json_output {
        ui::info("Scanning for CI/CD files...");
        ui::blank_line();
        ui::info(&format!(
            "Found {} file{}:",
            files.len(),
            if files.len() == 1 { "" } else { "s" }
        ));

        let max_path_len = files
            .iter()
            .map(|f| f.display_path.len())
            .max()
            .unwrap_or(0);
        let max_type_len = files
            .iter()
            .map(|f| f.ci_type.label().len())
            .max()
            .unwrap_or(0);

        for f in &files {
            println!(
                "  {:<width_path$}  {:<width_type$}  [{}]",
                f.display_path,
                f.ci_type.label(),
                f.relevance.status_label(),
                width_path = max_path_len,
                width_type = max_type_len,
            );
        }
        ui::blank_line();
    }

    let sendable: Vec<&ScannedFile> = files
        .iter()
        .filter(|f| f.relevance.should_send())
        .take(MAX_FILES_PER_REQUEST)
        .collect();

    if sendable.is_empty() {
        if auto_apply {
            let repo_config = seed_repo_config_from_files(&files)?;
            if let Some(workspace) = target_workspace.as_deref() {
                let config_result = ensure_repo_workspace_config(workspace)?;
                automation_report.repo_config = Some(RepoConfigAutomationReport {
                    path: config_result.path.display().to_string(),
                    workspace: config_result.workspace,
                    wrote: config_result.wrote || repo_config.as_ref().is_some_and(|r| r.wrote),
                    added_entries: repo_config.as_ref().map(|r| r.added_entries).unwrap_or(0),
                    added_profiles: repo_config.as_ref().map(|r| r.added_profiles).unwrap_or(0),
                });
            }
        }

        if !json_output {
            ui::info("No files need optimization.");
            print_repo_config_tip();
        } else {
            if automation_requested {
                print_automation_report(&mut automation_report)?;
            } else {
                println!("{{\"results\":[]}}");
            }
        }
        return Ok(());
    }

    let total_sendable = files.iter().filter(|f| f.relevance.should_send()).count();
    if !json_output {
        if total_sendable > MAX_FILES_PER_REQUEST {
            ui::warn(&format!(
                "Sending {} of {} optimizable files (limit: {} per request)",
                MAX_FILES_PER_REQUEST, total_sendable, MAX_FILES_PER_REQUEST
            ));
        } else {
            ui::info(&format!(
                "Sending {} file{} for optimization...",
                sendable.len(),
                if sendable.len() == 1 { "" } else { "s" }
            ));
        }
        ui::blank_line();
    }

    let (mut results, api_fallback) = run_deterministic_pass(&sendable, json_output);

    if !api_fallback.is_empty() {
        match ensure_ai_assist_ready(json_output).await {
            Ok(()) => {
                if !json_output {
                    ui::info(&format!(
                        "Deterministic pass skipped {} file{}; running AI assist fallback...",
                        api_fallback.len(),
                        if api_fallback.len() == 1 { "" } else { "s" }
                    ));
                    ui::blank_line();
                }

                let client = ApiClient::new()?;
                for file in api_fallback {
                    let request = OptimizeRequest {
                        files: vec![OptimizeFileRequest {
                            path: file.display_path.clone(),
                            content: file.content.clone(),
                            input_type: file.ci_type.api_key().map(String::from),
                        }],
                    };

                    match client.optimize(&request).await {
                        Ok(response) => results.extend(response.results),
                        Err(error) => {
                            if results.is_empty() && !automation_requested {
                                return Err(error);
                            }

                            if !json_output {
                                ui::warn(&format!(
                                    "AI assist fallback failed for {}: {error}",
                                    file.display_path
                                ));
                            }
                            results.push(ai_fallback_error_result(file, &error));
                        }
                    }
                }
            }
            Err(error) => {
                if results.is_empty() && !automation_requested {
                    return Err(error);
                }

                if !json_output {
                    ui::warn(&format!("Skipping AI assist fallback: {error}"));
                    ui::blank_line();
                }
                results.extend(
                    api_fallback
                        .iter()
                        .map(|file| ai_fallback_error_result(file, &error)),
                );
            }
        }
    }

    let repo_workspace_for_generated_workflows = target_workspace
        .clone()
        .or_else(|| discover_repo_config_workspace().ok().flatten());
    prefer_repo_config_workspace_in_results(
        &mut results,
        repo_workspace_for_generated_workflows.as_deref(),
    );

    if json_output && !automation_requested {
        let response = OptimizeResponse { results };
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    automation_report.optimize_results = results.clone();
    let mut files_to_apply: Vec<ProposedChange<'_>> = Vec::new();
    let sendable_by_path: HashMap<&str, &ScannedFile> = sendable
        .iter()
        .map(|f| (f.display_path.as_str(), *f))
        .collect();

    for result in &results {
        let original_file = sendable_by_path.get(result.path.as_str()).copied();

        if !json_output {
            println!("── {} ──", result.path);
        }

        match result.status.as_str() {
            "optimized" => {
                if !json_output && !result.changes.is_empty() {
                    println!("Changes:");
                    for (i, change) in result.changes.iter().enumerate() {
                        println!("  {}. {}", i + 1, change.description);
                    }
                    println!();
                }

                if let (Some(optimized), Some(original)) =
                    (&result.optimized_content, original_file)
                {
                    if let Err(reason) = validate_output(&original.content, optimized) {
                        if !json_output {
                            ui::error(&format!("Output validation failed: {}", reason));
                            println!();
                        }
                        continue;
                    }

                    let final_content = preserve_trailing_newline(&original.content, optimized);
                    let analysis =
                        analyze_optimization(&original.content, &final_content, original.ci_type);
                    if !json_output {
                        print_colored_diff(&original.content, &final_content);
                        print_analysis(&analysis);
                    }
                    files_to_apply.push(ProposedChange {
                        file: original,
                        content: final_content,
                        analysis,
                    });
                }
            }
            "no_changes" => {
                if !json_output {
                    ui::info("Already optimized or no deterministic migration available.");
                }
            }
            "error" => {
                if !json_output {
                    if let Some(err) = &result.error {
                        ui::error(err);
                    } else {
                        ui::error("Unknown error");
                    }
                }
            }
            other => {
                if !json_output {
                    ui::warn(&format!("Unexpected status: {}", other));
                }
            }
        }

        if !json_output
            && let Some(explanation) = &result.explanation
            && !explanation.is_empty()
        {
            println!();
            ui::info(explanation);
        }

        if !json_output {
            println!();
        }
    }

    if files_to_apply.is_empty() {
        if auto_apply {
            let repo_config = seed_repo_config_from_files(&files)?;
            if let Some(workspace) = target_workspace.as_deref() {
                let config_result = ensure_repo_workspace_config(workspace)?;
                automation_report.repo_config = Some(RepoConfigAutomationReport {
                    path: config_result.path.display().to_string(),
                    workspace: config_result.workspace,
                    wrote: config_result.wrote || repo_config.as_ref().is_some_and(|r| r.wrote),
                    added_entries: repo_config.as_ref().map(|r| r.added_entries).unwrap_or(0),
                    added_profiles: repo_config.as_ref().map(|r| r.added_profiles).unwrap_or(0),
                });
            }
        }
        if json_output && automation_requested {
            print_automation_report(&mut automation_report)?;
        }
        return Ok(());
    }

    if dry_run {
        if json_output && automation_requested {
            print_automation_report(&mut automation_report)?;
        }
        return Ok(());
    }

    let high_risk_count = files_to_apply
        .iter()
        .filter(|change| change.analysis.risk.level == RiskLevel::High)
        .count();

    if !json_output && high_risk_count > 0 {
        ui::warn(&format!(
            "{} high-risk change{} detected. Review the risk report before applying.",
            high_risk_count,
            if high_risk_count == 1 { "" } else { "s" }
        ));
    }

    let should_apply = if auto_apply {
        true
    } else if std::io::stdin().is_terminal() {
        prompt_apply()?
    } else {
        if !json_output {
            ui::info("Use --apply to apply changes non-interactively.");
        }
        false
    };

    let allow_high_risk = if high_risk_count == 0 {
        true
    } else if auto_apply {
        if !json_output {
            ui::warn("Skipping high-risk changes in --apply mode for safety.");
        }
        false
    } else if std::io::stdin().is_terminal() {
        prompt_apply_high_risk()?
    } else {
        if !json_output {
            ui::warn("Use interactive mode to apply high-risk changes after review.");
        }
        false
    };

    if should_apply {
        let mut written = 0usize;
        for change in &files_to_apply {
            if change.analysis.risk.level == RiskLevel::High && !allow_high_risk {
                if !json_output {
                    ui::warn(&format!(
                        "Skipped high-risk change: {}",
                        change.file.display_path
                    ));
                }
                continue;
            }

            std::fs::write(&change.file.path, &change.content)?;
            if !json_output {
                ui::info(&format!("Written: {}", change.file.display_path));
            }
            written += 1;
        }

        if written == 0 {
            if !json_output {
                ui::warn("No files were written.");
            }
        } else {
            let repo_config = seed_repo_config_from_files(&files)?;
            let workspace_config = target_workspace
                .as_deref()
                .map(ensure_repo_workspace_config)
                .transpose()?;
            if !json_output {
                ui::blank_line();
            }
            if !json_output && let Some(result) = &repo_config {
                ui::info(&format!(
                    "Seeded repo config: {}",
                    result.config_path.display()
                ));
                ui::info(&format!(
                    "Added {} entr{} and {} profile{}.",
                    result.added_entries,
                    if result.added_entries == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    result.added_profiles,
                    if result.added_profiles == 1 { "" } else { "s" }
                ));
                ui::blank_line();
            }
            if let Some(result) = workspace_config {
                automation_report.repo_config = Some(RepoConfigAutomationReport {
                    path: result.path.display().to_string(),
                    workspace: result.workspace,
                    wrote: result.wrote || repo_config.as_ref().is_some_and(|r| r.wrote),
                    added_entries: repo_config.as_ref().map(|r| r.added_entries).unwrap_or(0),
                    added_profiles: repo_config.as_ref().map(|r| r.added_profiles).unwrap_or(0),
                });
            }
            if !json_output {
                ui::info("Done! Next steps:");
                ui::info("  1. Review: git diff");
                ui::info("  2. Commit and push to trigger your first cached CI run");
                if let Some(result) = repo_config {
                    ui::info(&format!(
                        "  3. Review repo config: {}",
                        result.config_path.display()
                    ));
                } else {
                    print_repo_config_tip();
                }

                if let Ok(config) = Config::load()
                    && let Some(ref ws) = config.default_workspace
                {
                    ui::blank_line();
                    ui::info(&format!("Your workspace: {}", ws));
                }
            }
        }
    }

    if json_output && automation_requested {
        print_automation_report(&mut automation_report)?;
    }

    Ok(())
}

fn print_automation_report(report: &mut OnboardAutomationReport) -> Result<()> {
    report.next_steps = next_steps_for_onboard(report);
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn next_steps_for_onboard(report: &OnboardAutomationReport) -> Vec<String> {
    let optimized_workflow = report
        .optimize_results
        .iter()
        .any(|result| result.status == "optimized");
    let repo_config_changed = report.repo_config.as_ref().is_some_and(|config| {
        config.wrote || config.added_entries > 0 || config.added_profiles > 0
    });
    let printed_ci_token_values = report
        .ci_tokens
        .as_ref()
        .is_some_and(|tokens| tokens.restore_value.is_some() || tokens.save_value.is_some());
    let github_secrets_ready = report.github_secrets.is_some();

    let mut steps = Vec::new();
    if repo_config_changed {
        steps.push("Review .boringcache.toml before committing.".to_string());
    }
    if optimized_workflow {
        steps.push("Review the generated workflow diff before committing.".to_string());
    }
    if printed_ci_token_values {
        steps.push(
            "Store BORINGCACHE_RESTORE_TOKEN and BORINGCACHE_SAVE_TOKEN as CI secrets; do not commit token values."
                .to_string(),
        );
    } else if optimized_workflow && !github_secrets_ready {
        steps.push(
            "Make sure CI has BORINGCACHE_RESTORE_TOKEN and BORINGCACHE_SAVE_TOKEN before relying on the workflow."
                .to_string(),
        );
    }
    if repo_config_changed || optimized_workflow {
        steps.push("Commit and push to trigger the first cached CI run.".to_string());
    } else if github_secrets_ready {
        steps.push("Rerun CI so jobs can pick up the BoringCache secrets.".to_string());
    }
    if report.repo_config.is_some() || optimized_workflow {
        steps.push(
            "Use `boringcache doctor --json` for auth/workspace checks and `boringcache audit --json` when cache paths change."
                .to_string(),
        );
    }

    steps
}

#[derive(Debug, Clone)]
struct WorkspaceSelection {
    workspace: String,
    should_provision: bool,
}

async fn select_interactive_workspace_for_repo() -> Result<Option<WorkspaceSelection>> {
    if let Some(workspace) = discover_repo_config_workspace()? {
        ui::info(&format!("Using repo workspace: {workspace}"));
        return Ok(Some(WorkspaceSelection {
            workspace,
            should_provision: false,
        }));
    }

    let client = ApiClient::new()?;
    let mut workspaces = match client.list_workspaces().await {
        Ok(workspaces) => workspaces,
        Err(error) => {
            ui::warn(&format!("Could not list workspaces automatically: {error}"));
            Vec::new()
        }
    };
    workspaces.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.slug.cmp(&b.slug)));

    if workspaces.is_empty() {
        ui::blank_line();
        ui::info("No workspaces are visible for this token yet.");
        let workspace = normalize_workspace_path(&prompt_non_empty(
            "Workspace to create or use (namespace/workspace): ",
        )?)?;
        return Ok(Some(WorkspaceSelection {
            workspace,
            should_provision: true,
        }));
    }

    if workspaces.len() == 1 {
        let workspace = workspaces[0].slug.clone();
        ui::info(&format!("Using workspace: {workspace}"));
        return Ok(Some(WorkspaceSelection {
            workspace,
            should_provision: false,
        }));
    }

    ui::blank_line();
    ui::info("Choose the workspace for this repo:");
    for (index, workspace) in workspaces.iter().enumerate() {
        ui::info(&format!(
            "  {}. {} ({})",
            index + 1,
            workspace.name,
            workspace.slug
        ));
    }

    loop {
        let raw = prompt_non_empty("Workspace number, or namespace/workspace to create/use: ")?;
        if let Ok(value) = raw.parse::<usize>()
            && value >= 1
            && value <= workspaces.len()
        {
            return Ok(Some(WorkspaceSelection {
                workspace: workspaces[value - 1].slug.clone(),
                should_provision: false,
            }));
        }

        match normalize_workspace_path(&raw) {
            Ok(workspace) => {
                let should_provision = !workspaces
                    .iter()
                    .any(|candidate| candidate.slug == workspace);
                return Ok(Some(WorkspaceSelection {
                    workspace,
                    should_provision,
                }));
            }
            Err(_) => ui::warn("Invalid selection. Enter a listed number or namespace/workspace."),
        }
    }
}

fn discover_repo_config_workspace() -> Result<Option<String>> {
    let cwd = std::env::current_dir().context("Failed to read current directory")?;
    let root = crate::commands::audit::discover_repo_root(&cwd)?;
    let Some(loaded) = crate::project_config::discover(&root)? else {
        return Ok(None);
    };
    loaded
        .config
        .workspace
        .as_deref()
        .map(normalize_workspace_path)
        .transpose()
}

fn record_repo_workspace_config(
    workspace: &str,
    automation_report: &mut OnboardAutomationReport,
) -> Result<()> {
    let config_result = ensure_repo_workspace_config(workspace)?;
    if config_result.wrote {
        ui::info(&format!(
            "Saved repo workspace config: {}",
            config_result.path.display()
        ));
    } else {
        ui::info(&format!(
            "Repo workspace config already set: {}",
            config_result.path.display()
        ));
    }

    automation_report.repo_config = Some(RepoConfigAutomationReport {
        path: config_result.path.display().to_string(),
        workspace: config_result.workspace,
        wrote: config_result.wrote,
        added_entries: 0,
        added_profiles: 0,
    });

    Ok(())
}

async fn maybe_setup_github_secrets_interactively(
    workspace: &str,
    explicit_repo: Option<&str>,
    rotate: bool,
    json_output: bool,
    automation_report: &mut OnboardAutomationReport,
) -> Result<()> {
    let repo = explicit_repo
        .map(ToOwned::to_owned)
        .or_else(infer_github_repo_from_origin);
    let Some(repo) = repo else {
        ui::warn("Could not infer a GitHub repository from git remote origin.");
        ui::info(
            "Skip GitHub secrets for now, or rerun with --github-secrets --github-repo OWNER/REPO.",
        );
        return Ok(());
    };

    if !prompt_yes_no(
        &format!("Set GitHub Actions BoringCache secrets for {repo}? [Y/n] "),
        true,
    )? {
        ui::info("Skipped GitHub secrets.");
        return Ok(());
    }

    match ensure_github_split_secrets(workspace, &repo, rotate, json_output, automation_report)
        .await
    {
        Ok(secret_report) => {
            automation_report.github_secrets = Some(secret_report);
        }
        Err(error) => {
            ui::warn(&format!(
                "Could not set GitHub secrets automatically: {error}"
            ));
            ui::info(&format!(
                "After authenticating GitHub CLI, rerun: boringcache onboard --workspace {workspace} --github-secrets --github-repo {repo}"
            ));
        }
    }

    Ok(())
}

async fn provision_workspace(
    workspace: &str,
    workspace_name: Option<&str>,
) -> Result<crate::api::models::workspace::WorkspaceProvisionResponse> {
    let client = ApiClient::for_admin()?;
    client
        .provision_workspace(&WorkspaceProvisionRequest {
            workspace: WorkspaceProvisionParams {
                slug: workspace.to_string(),
                name: workspace_name.map(ToOwned::to_owned),
                description: None,
                visibility: Some("private".to_string()),
            },
        })
        .await
}

async fn create_ci_token_pair(workspace: &str) -> Result<WorkspaceTokenPairResponse> {
    let client = ApiClient::for_admin()?;
    client
        .create_workspace_token_pair(
            workspace,
            &WorkspaceTokenPairCreateRequest {
                token_pair: WorkspaceTokenPairCreateParams {
                    name_prefix: Some("GitHub Actions".to_string()),
                    save_tag_prefixes: Vec::new(),
                    expiration_preset: None,
                    custom_expires_on: None,
                },
            },
        )
        .await
}

async fn ensure_github_split_secrets(
    workspace: &str,
    repo: &str,
    rotate: bool,
    json_output: bool,
    automation_report: &mut OnboardAutomationReport,
) -> Result<GithubSecretsAutomationReport> {
    let existing = github_existing_secret_names(repo)?;
    let required = ["BORINGCACHE_RESTORE_TOKEN", "BORINGCACHE_SAVE_TOKEN"];

    if !rotate && required.iter().all(|name| existing.contains(*name)) {
        if !json_output {
            ui::info(&format!("GitHub secrets already set for {repo}."));
        }
        return Ok(GithubSecretsAutomationReport {
            repo: repo.to_string(),
            status: "already_set".to_string(),
            updated: Vec::new(),
        });
    }

    let token_pair = create_ci_token_pair(workspace).await?;
    set_github_secret(repo, "BORINGCACHE_RESTORE_TOKEN", &token_pair.restore.value)?;
    set_github_secret(repo, "BORINGCACHE_SAVE_TOKEN", &token_pair.save.value)?;

    if !json_output {
        ui::info(&format!("Updated GitHub BoringCache secrets for {repo}."));
    }

    automation_report.ci_tokens = Some(ci_token_report(&token_pair, false));

    Ok(GithubSecretsAutomationReport {
        repo: repo.to_string(),
        status: if rotate {
            "rotated".to_string()
        } else {
            "updated".to_string()
        },
        updated: required.iter().map(|name| name.to_string()).collect(),
    })
}

fn ci_token_report(
    token_pair: &WorkspaceTokenPairResponse,
    reveal_values: bool,
) -> CiTokenAutomationReport {
    CiTokenAutomationReport {
        status: "created".to_string(),
        restore_token_id: token_pair.restore.token.id.clone(),
        save_token_id: token_pair.save.token.id.clone(),
        restore_value: reveal_values.then(|| token_pair.restore.value.clone()),
        save_value: reveal_values.then(|| token_pair.save.value.clone()),
    }
}

#[derive(Debug, Deserialize)]
struct GithubSecretListItem {
    name: String,
}

fn infer_github_repo_from_origin() -> Option<String> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let remote = String::from_utf8(output.stdout).ok()?;
    parse_github_repo_from_remote(&remote)
}

fn parse_github_repo_from_remote(remote: &str) -> Option<String> {
    let remote = remote.trim().trim_end_matches('/');
    let path = remote
        .strip_prefix("git@github.com:")
        .or_else(|| remote.strip_prefix("https://github.com/"))
        .or_else(|| remote.strip_prefix("http://github.com/"))
        .or_else(|| remote.strip_prefix("ssh://git@github.com/"))?;
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if parts.next().is_some() || !valid_github_repo_part(owner) || !valid_github_repo_part(repo) {
        return None;
    }

    Some(format!("{owner}/{repo}"))
}

fn valid_github_repo_part(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('.')
        && !part.ends_with('.')
        && part
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
}

fn github_existing_secret_names(repo: &str) -> Result<HashSet<String>> {
    let output = Command::new("gh")
        .args(["secret", "list", "--repo", repo, "--json", "name"])
        .output()
        .with_context(
            || "Failed to run `gh secret list`. Install GitHub CLI and authenticate it.",
        )?;

    if !output.status.success() {
        anyhow::bail!(
            "gh secret list failed for {repo}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let secrets: Vec<GithubSecretListItem> = serde_json::from_slice(&output.stdout)
        .with_context(|| "Failed to parse `gh secret list --json name` output")?;
    Ok(secrets.into_iter().map(|secret| secret.name).collect())
}

fn set_github_secret(repo: &str, name: &str, value: &str) -> Result<()> {
    let mut child = Command::new("gh")
        .args(["secret", "set", name, "--repo", repo])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to run `gh secret set {name}`"))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("Failed to open stdin for `gh secret set`")?;
        stdin
            .write_all(value.as_bytes())
            .with_context(|| format!("Failed to pass {name} to `gh secret set`"))?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("Failed to wait for `gh secret set {name}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "gh secret set {name} failed for {repo}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn ensure_repo_workspace_config(workspace: &str) -> Result<RepoWorkspaceConfigResult> {
    let cwd = std::env::current_dir().context("Failed to read current directory")?;
    let root = crate::commands::audit::discover_repo_root(&cwd)?;
    let loaded = crate::project_config::discover(&root)?;
    let config_path = loaded
        .as_ref()
        .map(|loaded| loaded.path.clone())
        .unwrap_or_else(|| root.join(".boringcache.toml"));
    let mut config = loaded.map(|loaded| loaded.config).unwrap_or_default();

    let wrote = config.workspace.as_deref() != Some(workspace);
    if wrote {
        config.workspace = Some(workspace.to_string());
        let contents = toml::to_string_pretty(&config).context("Failed to render repo config")?;
        std::fs::write(&config_path, contents)
            .with_context(|| format!("Failed to write {}", config_path.display()))?;
    }

    Ok(RepoWorkspaceConfigResult {
        path: config_path,
        workspace: workspace.to_string(),
        wrote,
    })
}

fn normalize_workspace_path(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_lowercase();
    let parts: Vec<&str> = normalized.split('/').collect();
    if parts.len() != 2
        || !valid_workspace_slug_part(parts[0])
        || !valid_workspace_slug_part(parts[1])
    {
        anyhow::bail!(
            "Invalid workspace '{}'. Use namespace/workspace with lowercase letters, numbers, and hyphens.",
            raw
        );
    }

    Ok(normalized)
}

fn valid_workspace_slug_part(value: &str) -> bool {
    value.len() >= 2
        && value.len() <= 50
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && value
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
}

fn print_repo_config_tip() {
    ui::blank_line();
    ui::info("Optional later: if you already use raw tag:path pairs and want repo config:");
    ui::info("  boringcache audit --write");
}

fn seed_repo_config_from_files(
    files: &[ScannedFile],
) -> Result<Option<crate::commands::audit::RepoConfigWriteResult>> {
    let scan_paths = files
        .iter()
        .map(|file| file.display_path.clone())
        .collect::<Vec<_>>();
    let result = crate::commands::audit::write_repo_config_for_paths(None, &scan_paths)?;
    if result.wrote {
        Ok(Some(result))
    } else {
        Ok(None)
    }
}

fn run_deterministic_pass<'a>(
    files: &[&'a ScannedFile],
    json_output: bool,
) -> (Vec<OptimizeFileResult>, Vec<&'a ScannedFile>) {
    let mut results = Vec::new();
    let mut api_fallback = Vec::new();

    for file in files {
        match deterministic_optimize(file.ci_type, &file.content) {
            TransformResult::Optimized {
                optimized_content,
                changes,
                explanation,
            } => {
                let normalized = preserve_trailing_newline(&file.content, &optimized_content);
                match validate_output(&file.content, &normalized) {
                    Ok(()) => {
                        results.push(OptimizeFileResult {
                            path: file.display_path.clone(),
                            status: "optimized".to_string(),
                            detected_type: file.ci_type.api_key().map(str::to_string),
                            optimized_content: Some(normalized),
                            changes,
                            explanation: Some(explanation),
                            error: None,
                        });
                    }
                    Err(reason) => {
                        if !json_output {
                            ui::warn(&format!(
                                "Deterministic output failed validation for {}: {}",
                                file.display_path, reason
                            ));
                        }
                        api_fallback.push(*file);
                    }
                }
            }
            TransformResult::NoChanges { reason } | TransformResult::Unsupported { reason } => {
                if !json_output {
                    ui::info(&format!("{}: {}", file.display_path, reason));
                }
                api_fallback.push(*file);
            }
        }
    }

    (results, api_fallback)
}

fn ai_fallback_error_result(file: &ScannedFile, error: &anyhow::Error) -> OptimizeFileResult {
    OptimizeFileResult {
        path: file.display_path.clone(),
        status: "error".to_string(),
        detected_type: file.ci_type.api_key().map(str::to_string),
        optimized_content: None,
        changes: Vec::new(),
        explanation: Some(
            "AI assist fallback did not complete. Core onboarding can continue.".to_string(),
        ),
        error: Some(error.to_string()),
    }
}

fn prefer_repo_config_workspace_in_results(
    results: &mut [OptimizeFileResult],
    repo_workspace: Option<&str>,
) {
    if repo_workspace.is_none() {
        return;
    }

    for result in results {
        let Some(content) = result.optimized_content.as_deref() else {
            continue;
        };
        let normalized = strip_dynamic_github_workspace_from_boringcache_steps(content);
        if normalized == content {
            continue;
        }

        result.optimized_content = Some(normalized);
        result.changes.push(OptimizeChange {
            description: "Let boringcache/one resolve the workspace from .boringcache.toml"
                .to_string(),
            before_snippet: Some("workspace: ${{ github.repository }}".to_string()),
            after_snippet: None,
        });
    }
}

fn strip_dynamic_github_workspace_from_boringcache_steps(content: &str) -> String {
    let has_trailing_newline = content.ends_with('\n');
    let mut rebuilt = Vec::new();
    let mut removed = false;
    let mut boringcache_step_indent = None;

    for line in content.lines() {
        let indent = count_leading_spaces(line);
        let trimmed = line.trim_start();

        if let Some(step_indent) = boringcache_step_indent
            && !trimmed.is_empty()
            && indent <= step_indent
            && trimmed.starts_with("- ")
            && !line_is_boringcache_action_reference(line)
        {
            boringcache_step_indent = None;
        }

        if line_is_boringcache_action_reference(line) {
            boringcache_step_indent = Some(boringcache_step_indent_for_line(line));
        }

        if boringcache_step_indent.is_some() && line_is_dynamic_github_workspace_input(line) {
            removed = true;
            continue;
        }

        rebuilt.push(line);
    }

    if !removed {
        return content.to_string();
    }

    let mut output = rebuilt.join("\n");
    if has_trailing_newline {
        output.push('\n');
    }
    output
}

fn line_is_boringcache_action_reference(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("- uses: boringcache/one")
        || trimmed.starts_with("uses: boringcache/one")
        || trimmed.starts_with("- uses: \"boringcache/one")
        || trimmed.starts_with("uses: \"boringcache/one")
        || trimmed.starts_with("- uses: 'boringcache/one")
        || trimmed.starts_with("uses: 'boringcache/one")
}

fn boringcache_step_indent_for_line(line: &str) -> usize {
    let indent = count_leading_spaces(line);
    if line.trim_start().starts_with("- ") {
        indent
    } else {
        indent.saturating_sub(2)
    }
}

fn line_is_dynamic_github_workspace_input(line: &str) -> bool {
    let Some(value) = line.trim_start().strip_prefix("workspace:") else {
        return false;
    };
    value.contains("github.repository")
}

fn scan_single_file(path: &str) -> Result<Vec<ScannedFile>> {
    let path = PathBuf::from(path);
    if !path.exists() {
        anyhow::bail!("File not found: {}", path.display());
    }

    let content = std::fs::read_to_string(&path)?;
    if content.contains('\0') {
        anyhow::bail!("File appears to be binary: {}", path.display());
    }

    let display_path = path
        .strip_prefix(std::env::current_dir().unwrap_or_default())
        .unwrap_or(&path)
        .to_string_lossy()
        .to_string();

    let ci_type = detect_ci_type(&display_path, &content);
    let relevance = score_relevance(&content, ci_type);

    Ok(vec![ScannedFile {
        path,
        display_path,
        content,
        ci_type,
        relevance,
    }])
}

fn scan_project() -> Result<Vec<ScannedFile>> {
    let cwd = std::env::current_dir()?;
    let mut files = Vec::new();

    scan_glob(&cwd, ".github/workflows", &["yml", "yaml"], &mut files);

    scan_exact(&cwd, ".gitlab-ci.yml", &mut files);
    scan_exact(&cwd, ".circleci/config.yml", &mut files);
    scan_exact(&cwd, ".buildkite/pipeline.yml", &mut files);
    scan_exact(&cwd, ".buildkite/pipeline.yaml", &mut files);
    scan_exact(&cwd, ".travis.yml", &mut files);
    scan_exact(&cwd, "azure-pipelines.yml", &mut files);
    scan_exact(&cwd, "bitbucket-pipelines.yml", &mut files);
    scan_exact(&cwd, ".drone.yml", &mut files);
    scan_exact(&cwd, "Jenkinsfile", &mut files);

    Ok(files)
}

fn scan_exact(root: &Path, relative: &str, files: &mut Vec<ScannedFile>) {
    let path = root.join(relative);
    if let Some(file) = try_read_file(&path, relative) {
        files.push(file);
    }
}

fn scan_glob(root: &Path, dir: &str, extensions: &[&str], files: &mut Vec<ScannedFile>) {
    let dir_path = root.join(dir);
    // Onboarding scans known config directories under the local project root.
    // codeql[rust/path-injection]
    let entries = match std::fs::read_dir(&dir_path) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if extensions.contains(&ext) {
            let display = format!(
                "{}/{}",
                dir,
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            if let Some(file) = try_read_file(&path, &display) {
                files.push(file);
            }
        }
    }
}

fn try_read_file(path: &Path, display_path: &str) -> Option<ScannedFile> {
    // Onboarding only reads candidate config files discovered under the local project root.
    // codeql[rust/path-injection]
    let content = std::fs::read_to_string(path).ok()?;
    if content.contains('\0') {
        return None;
    }

    let ci_type = detect_ci_type(display_path, &content);
    let relevance = score_relevance(&content, ci_type);

    Some(ScannedFile {
        path: path.to_path_buf(),
        display_path: display_path.to_string(),
        content,
        ci_type,
        relevance,
    })
}

fn print_colored_diff(original: &str, optimized: &str) {
    let use_color = std::io::stdout().is_terminal();
    let diff = TextDiff::from_lines(original, optimized);

    for group in diff.grouped_ops(3) {
        for op in group {
            for change in diff.iter_changes(&op) {
                let (sign, color_code) = match change.tag() {
                    ChangeTag::Delete => ("-", "31"),
                    ChangeTag::Insert => ("+", "32"),
                    ChangeTag::Equal => (" ", ""),
                };

                let line = change.to_string_lossy();
                if use_color && !color_code.is_empty() {
                    print!("\x1b[{}m{}{}\x1b[0m", color_code, sign, line);
                } else {
                    print!("{}{}", sign, line);
                }
                if change.missing_newline() {
                    println!();
                }
            }
        }
    }
}

fn prompt_apply() -> Result<bool> {
    eprint!("Apply changes? [Y/n] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();
    Ok(trimmed.is_empty() || trimmed == "y" || trimmed == "yes")
}

fn prompt_apply_high_risk() -> Result<bool> {
    eprint!("Apply high-risk cache path changes as well? [y/N] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

fn prompt_yes_no(message: &str, default_yes: bool) -> Result<bool> {
    eprint!("{message}");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_lowercase();
    if trimmed.is_empty() {
        return Ok(default_yes);
    }
    Ok(trimmed == "y" || trimmed == "yes")
}

fn prompt_non_empty(message: &str) -> Result<String> {
    loop {
        eprint!("{message}");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let value = input.trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
        ui::warn("Input cannot be empty.");
    }
}

fn normalize_optional_input(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

async fn ensure_ai_assist_ready(json_output: bool) -> Result<()> {
    if optimize_auth_configured() {
        return Ok(());
    }

    if json_output || !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "AI assist fallback requires authentication. Run 'boringcache onboard' interactively or 'boringcache auth --token <token>' first."
        );
    }

    anyhow::bail!(
        "Authentication required for AI assist fallback. Run 'boringcache auth --token <token>' first."
    );
}

pub(crate) async fn run_cli_connect_onboarding(
    manual: bool,
    email_auth: Option<CliEmailAuthOptions>,
    token_scope: CliConnectTokenScope,
) -> Result<String> {
    let client = ApiClient::new()?;
    let connect = client.create_cli_connect_session(token_scope).await?;

    ui::blank_line();
    let email_auth_selected = email_auth.is_some();

    if let Some(email_auth) = email_auth {
        ui::info(match token_scope {
            CliConnectTokenScope::User => "Continue account sign-in by email:",
            CliConnectTokenScope::Workspace => "Continue onboarding by email:",
        });
        ui::info(&format!("  Email: {}", email_auth.email));
        ui::info(&format!("  Browser fallback: {}", connect.authorize_url));
        start_cli_connect_email_auth(&client, &connect.session_id, email_auth).await?;
    } else {
        ui::info(match token_scope {
            CliConnectTokenScope::User => "Approve account sign-in:",
            CliConnectTokenScope::Workspace => "Approve CLI access:",
        });
        ui::info(&format!("  1. Open {}", connect.verification_url));
        ui::info(&format!("  2. Enter code {}", connect.user_code));
        ui::info(&format!("  Direct link: {}", connect.authorize_url));

        if !manual && try_open_browser(&connect.authorize_url) {
            ui::info("Opened authorization page automatically.");
        } else if manual {
            ui::info(
                "Manual mode: open the verification URL on this machine or another device. The CLI will keep waiting for approval.",
            );
        } else {
            ui::info("Could not open browser automatically. Open the verification URL manually.");
        }
    }

    if email_auth_selected {
        ui::info("Waiting for email confirmation and browser approval...");
    } else {
        ui::info("Waiting for browser approval...");
    }
    let poll_interval = Duration::from_secs(connect.poll_interval_seconds.clamp(1, 10));
    let expires_at = parse_cli_connect_expiry(&connect.expires_at);

    loop {
        if expires_at.is_some_and(|deadline| Utc::now() >= deadline) {
            anyhow::bail!("CLI connect session expired before approval. Restart onboard.");
        }

        let poll = client
            .poll_cli_connect_session(&connect.session_id, &connect.poll_token)
            .await?;

        match poll.status.as_str() {
            "pending" => {
                tokio::time::sleep(poll_interval).await;
            }
            "approved" => {
                if let Some(token) = poll.token {
                    ui::info("CLI access approved.");
                    return Ok(token);
                }
                tokio::time::sleep(poll_interval).await;
            }
            "expired" => {
                anyhow::bail!("CLI connect session expired. Restart onboard.");
            }
            "consumed" => {
                anyhow::bail!("CLI connect token was already consumed. Restart onboard.");
            }
            other => {
                anyhow::bail!("Unexpected CLI connect status '{other}'. Restart onboard.");
            }
        }
    }
}

async fn start_cli_connect_email_auth(
    client: &ApiClient,
    session_id: &str,
    mut email_auth: CliEmailAuthOptions,
) -> Result<()> {
    ensure_email_signup_details(&mut email_auth)?;

    loop {
        let response = client
            .start_cli_connect_email_auth(
                session_id,
                &crate::api::models::cli_connect::CliConnectEmailAuthRequest {
                    email: email_auth.email.clone(),
                    name: email_auth.name.clone(),
                    username: email_auth.username.clone(),
                },
            )
            .await?;

        match response.status.as_str() {
            "email_sent" => {
                if let Some(next_step) = response.next_step.as_deref() {
                    ui::info(next_step);
                }
                return Ok(());
            }
            "signup_details_invalid" => {
                ui::warn("The account details for a new signup need another pass.");

                if let Some(errors) = response.field_errors.get("name") {
                    for error in errors {
                        ui::warn(&format!("Display name: {error}"));
                    }
                    email_auth.name = Some(prompt_non_empty("Display name: ")?);
                }

                if let Some(errors) = response.field_errors.get("username") {
                    for error in errors {
                        ui::warn(&format!("Username: {error}"));
                    }
                    email_auth.username = Some(prompt_non_empty("Username: ")?);
                }
            }
            other => anyhow::bail!("Unexpected CLI email auth status '{other}'."),
        }
    }
}

fn ensure_email_signup_details(email_auth: &mut CliEmailAuthOptions) -> Result<()> {
    if email_auth.name.is_some() && email_auth.username.is_some() {
        return Ok(());
    }

    ui::info("If this email is new, the CLI can create the account from here.");

    if email_auth.name.is_none() {
        email_auth.name = Some(prompt_non_empty("Display name (used only if needed): ")?);
    }

    if email_auth.username.is_none() {
        email_auth.username = Some(prompt_non_empty("Username (used only if needed): ")?);
    }

    Ok(())
}

fn parse_cli_connect_expiry(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn try_open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(url)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = url;
        false
    }
}

fn optimize_auth_configured() -> bool {
    if config::env_var("BORINGCACHE_API_TOKEN").is_some() {
        return true;
    }

    Config::load()
        .map(|cfg| !cfg.token.trim().is_empty())
        .unwrap_or(false)
}

pub async fn ensure_default_workspace_after_onboarding(token: &str) -> Result<()> {
    if config::env_var("BORINGCACHE_DEFAULT_WORKSPACE").is_some() {
        return Ok(());
    }

    let mut config = match Config::load() {
        Ok(cfg) => cfg,
        Err(_) => return Ok(()),
    };

    if config
        .default_workspace
        .as_ref()
        .is_some_and(|ws| !ws.trim().is_empty())
    {
        return Ok(());
    }

    let client = ApiClient::new_with_token_override(Some(token.to_string()))?;
    let mut workspaces = client.list_workspaces().await.unwrap_or_default();
    if workspaces.is_empty() {
        ui::warn(
            "No workspaces found for this token. Set one later with 'boringcache config set default_workspace <namespace/workspace>'.",
        );
        return Ok(());
    }

    workspaces.sort_by(|a, b| a.name.cmp(&b.name));

    let selected_workspace = if workspaces.len() == 1 {
        let workspace = workspaces.remove(0).slug;
        ui::info(&format!("Default workspace set to: {}", workspace));
        workspace
    } else {
        ui::blank_line();
        ui::info("Available workspaces:");
        for (index, workspace) in workspaces.iter().enumerate() {
            ui::info(&format!(
                "  {}. {} ({})",
                index + 1,
                workspace.name,
                workspace.slug
            ));
        }

        let selection = loop {
            let raw = prompt_non_empty("Choose default workspace number: ")?;
            match raw.parse::<usize>() {
                Ok(value) if value >= 1 && value <= workspaces.len() => break value - 1,
                _ => ui::warn("Invalid selection. Enter one of the listed numbers."),
            }
        };

        workspaces[selection].slug.clone()
    };

    config.default_workspace = Some(selected_workspace.clone());
    config.save_config()?;
    ui::info(&format!("Saved default workspace: {}", selected_workspace));

    Ok(())
}

fn analyze_optimization(original: &str, optimized: &str, ci_type: CiType) -> OptimizationAnalysis {
    let cache_paths = extract_cache_paths(optimized);
    let risk = assess_cache_risk(&cache_paths);
    let savings = estimate_savings(original, ci_type, &cache_paths);
    OptimizationAnalysis { risk, savings }
}

fn print_analysis(analysis: &OptimizationAnalysis) {
    println!(
        "Risk: {} ({})",
        analysis.risk.level.label(),
        analysis.risk.summary
    );
    if !analysis.risk.paths.is_empty() {
        println!("Cache paths: {}", analysis.risk.paths.join(", "));
    }
    println!(
        "Estimated savings: {}-{}s/run ({}-{}%), confidence: {}, baseline: {}",
        analysis.savings.min_seconds,
        analysis.savings.max_seconds,
        analysis.savings.min_percent,
        analysis.savings.max_percent,
        analysis.savings.confidence,
        analysis.savings.baseline
    );
    println!();
}

fn extract_cache_paths(content: &str) -> Vec<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut index = 0usize;
    let mut paths = Vec::new();

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("path:") {
            let rest = rest.trim();
            if rest == "|" || rest == ">" {
                let indent = count_leading_spaces(line);
                index += 1;
                while index < lines.len() {
                    let next = lines[index];
                    if next.trim().is_empty() {
                        index += 1;
                        continue;
                    }

                    if count_leading_spaces(next) <= indent {
                        break;
                    }

                    let candidate = clean_path_token(next.trim().trim_start_matches("- ").trim());
                    if is_path_like(candidate.as_str()) {
                        paths.push(candidate);
                    }
                    index += 1;
                }
                continue;
            }

            let candidate = clean_path_token(rest);
            if is_path_like(candidate.as_str()) {
                paths.push(candidate);
            }
        }

        if let Some(rest) = trimmed.strip_prefix("entries:") {
            extract_paths_from_entries(rest.trim(), &mut paths);
        }

        if trimmed.contains("boringcache restore") || trimmed.contains("boringcache save") {
            extract_paths_from_cli_line(trimmed, &mut paths);
        }

        index += 1;
    }

    paths.sort();
    paths.dedup();
    paths
}

fn extract_paths_from_entries(entries: &str, out: &mut Vec<String>) {
    for part in entries.split(',') {
        let cleaned = clean_path_token(part.trim());
        if cleaned.contains("://") {
            continue;
        }

        if let Some((_, path)) = cleaned.split_once(':') {
            let cache_path = clean_path_token(path.trim());
            if is_path_like(cache_path.as_str()) {
                out.push(cache_path);
            }
        }
    }
}

fn extract_paths_from_cli_line(line: &str, out: &mut Vec<String>) {
    let mut quoted_segments = Vec::new();
    let mut active_quote = None;
    let mut current = String::new();

    for ch in line.chars() {
        match active_quote {
            Some(quote) if ch == quote => {
                if !current.is_empty() {
                    quoted_segments.push(current.clone());
                }
                current.clear();
                active_quote = None;
            }
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => {
                active_quote = Some(ch);
            }
            None => {}
        }
    }

    for segment in quoted_segments {
        extract_paths_from_entries(segment.as_str(), out);
    }

    for token in line.split_whitespace() {
        let cleaned = clean_path_token(token);
        if cleaned.contains("://") {
            continue;
        }

        if let Some((_, path)) = cleaned.split_once(':') {
            let candidate = clean_path_token(path.trim());
            if is_path_like(candidate.as_str()) {
                out.push(candidate);
            }
        }
    }
}

fn clean_path_token(token: &str) -> String {
    token
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`')
        .trim_matches(|c: char| c == ',' || c == ';')
        .to_string()
}

fn count_leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn is_path_like(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    value.contains('/')
        || value.starts_with('.')
        || value.starts_with('~')
        || value.starts_with('$')
        || value.contains("node_modules")
        || value.contains("vendor")
        || value.contains("cache")
        || value == "dist"
        || value == "build"
        || value == "target"
        || value == "coverage"
}

fn assess_cache_risk(paths: &[String]) -> RiskReport {
    if paths.is_empty() {
        return RiskReport {
            level: RiskLevel::Review,
            summary: "could not infer cache paths; manual review recommended".to_string(),
            paths: vec![],
        };
    }

    let high_markers = [
        ".env",
        "secret",
        "secrets",
        "token",
        "credential",
        "credentials",
        "id_rsa",
        "id_ed25519",
        ".ssh",
        ".aws",
        ".gnupg",
        "kubeconfig",
        ".pem",
        ".p12",
        ".key",
        "private",
        "database",
        ".db",
    ];
    let low_markers = [
        "node_modules",
        "vendor/bundle",
        ".npm",
        ".pnpm-store",
        ".yarn",
        ".cache/pip",
        ".cargo",
        ".gradle",
        ".m2",
        "go/pkg/mod",
        ".cache/go-build",
        "target",
    ];

    let mut high_paths = Vec::new();
    let mut review_paths = Vec::new();
    let mut low_paths = Vec::new();

    for path in paths {
        let lowered = path.to_lowercase();
        if high_markers.iter().any(|marker| lowered.contains(marker)) {
            high_paths.push(path.clone());
        } else if low_markers.iter().any(|marker| lowered.contains(marker)) {
            low_paths.push(path.clone());
        } else {
            review_paths.push(path.clone());
        }
    }

    if !high_paths.is_empty() {
        return RiskReport {
            level: RiskLevel::High,
            summary: "sensitive-looking paths detected; do not cache without explicit approval"
                .to_string(),
            paths: high_paths,
        };
    }

    if !review_paths.is_empty() {
        return RiskReport {
            level: RiskLevel::Review,
            summary: "mixed or unknown paths detected; verify these directories are safe to share"
                .to_string(),
            paths: review_paths,
        };
    }

    RiskReport {
        level: RiskLevel::Low,
        summary: "only dependency/tool cache paths detected".to_string(),
        paths: low_paths,
    }
}

fn estimate_savings(original: &str, ci_type: CiType, paths: &[String]) -> SavingsEstimate {
    let has_existing_cache = score_relevance(original, ci_type) == FileRelevance::HasCaching;
    let baseline = if has_existing_cache {
        "current cache baseline"
    } else {
        "no cache baseline"
    };

    let mut score: u32 = 0;
    for path in paths {
        let lowered = path.to_lowercase();
        if lowered.contains("node_modules")
            || lowered.contains("vendor/bundle")
            || lowered.contains(".cache/pip")
            || lowered.contains(".gradle")
            || lowered.contains(".cargo")
            || lowered.contains("go/pkg/mod")
        {
            score += 3;
        } else if lowered.contains("dist")
            || lowered.contains("build")
            || lowered.contains("target")
            || lowered.contains(".next")
        {
            score += 2;
        } else {
            score += 1;
        }
    }

    if score == 0 {
        score = 1;
    }

    if ci_type == CiType::Dockerfile {
        score += 1;
    }

    if has_existing_cache && score > 1 {
        score -= 1;
    }

    let min_seconds = (score * 15).clamp(10, 240);
    let max_seconds = if has_existing_cache {
        (score * 30).clamp(min_seconds + 10, 360)
    } else {
        (score * 55).clamp(min_seconds + 15, 600)
    };

    let (min_percent, max_percent) = if has_existing_cache {
        (
            ((4 + score) as u8).min(16),
            ((10 + (score * 2)) as u8).min(28),
        )
    } else {
        (
            ((8 + (score * 2)) as u8).min(32),
            ((16 + (score * 3)) as u8).min(55),
        )
    };

    let confidence = if paths.is_empty() {
        "low"
    } else if paths.len() >= 2 {
        "medium"
    } else {
        "medium-low"
    };

    SavingsEstimate {
        min_seconds,
        max_seconds,
        min_percent,
        max_percent,
        confidence,
        baseline,
    }
}

#[cfg(test)]
#[path = "onboard_tests.rs"]
mod tests;

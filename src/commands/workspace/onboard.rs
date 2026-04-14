use crate::api::client::ApiClient;
use crate::api::models::optimize::{
    OptimizeFileRequest, OptimizeFileResult, OptimizeRequest, OptimizeResponse,
};
use crate::config::{self, Config};
use crate::optimize::detect::{detect_ci_type, score_relevance};
use crate::optimize::transform::{
    TransformResult, deterministic_optimize, preserve_trailing_newline, validate_output,
};
use crate::optimize::{CiType, FileRelevance, MAX_FILES_PER_REQUEST};
use crate::types::Result;
use crate::ui;
use chrono::{DateTime, Utc};
use jwalk::WalkDir;
use similar::{ChangeTag, TextDiff};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
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

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    path: Option<String>,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
    auto_apply: bool,
    dry_run: bool,
    manual: bool,
    json_output: bool,
) -> Result<()> {
    if !json_output && std::io::stdin().is_terminal() {
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

            let token = match run_cli_connect_onboarding(manual, cli_email_auth).await {
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

    let files = if let Some(ref path) = path {
        scan_single_file(path)?
    } else {
        scan_project()?
    };

    if files.is_empty() {
        if json_output {
            println!("{{\"results\":[]}}");
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
        if !json_output {
            ui::info("No files need optimization.");
            print_repo_config_tip();
        } else {
            println!("{{\"results\":[]}}");
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

                let api_files: Vec<OptimizeFileRequest> = api_fallback
                    .iter()
                    .map(|f| OptimizeFileRequest {
                        path: f.display_path.clone(),
                        content: f.content.clone(),
                        input_type: f.ci_type.api_key().map(String::from),
                    })
                    .collect();

                let request = OptimizeRequest { files: api_files };
                let client = ApiClient::new()?;
                let response: OptimizeResponse = client.optimize(&request).await?;
                results.extend(response.results);
            }
            Err(error) => {
                if results.is_empty() {
                    return Err(error);
                }

                if !json_output {
                    ui::warn(&format!("Skipping AI assist fallback: {error}"));
                    ui::blank_line();
                }
            }
        }
    }

    if json_output {
        let response = OptimizeResponse { results };
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    let mut files_to_apply: Vec<ProposedChange<'_>> = Vec::new();
    let sendable_by_path: HashMap<&str, &ScannedFile> = sendable
        .iter()
        .map(|f| (f.display_path.as_str(), *f))
        .collect();

    for result in &results {
        let original_file = sendable_by_path.get(result.path.as_str()).copied();

        println!("── {} ──", result.path);

        match result.status.as_str() {
            "optimized" => {
                if !result.changes.is_empty() {
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
                        ui::error(&format!("Output validation failed: {}", reason));
                        println!();
                        continue;
                    }

                    let final_content = preserve_trailing_newline(&original.content, optimized);
                    let analysis =
                        analyze_optimization(&original.content, &final_content, original.ci_type);
                    print_colored_diff(&original.content, &final_content);
                    print_analysis(&analysis);
                    files_to_apply.push(ProposedChange {
                        file: original,
                        content: final_content,
                        analysis,
                    });
                }
            }
            "no_changes" => {
                ui::info("Already optimized or no deterministic migration available.");
            }
            "error" => {
                if let Some(err) = &result.error {
                    ui::error(err);
                } else {
                    ui::error("Unknown error");
                }
            }
            other => {
                ui::warn(&format!("Unexpected status: {}", other));
            }
        }

        if let Some(explanation) = &result.explanation
            && !explanation.is_empty()
        {
            println!();
            ui::info(explanation);
        }

        println!();
    }

    if files_to_apply.is_empty() {
        return Ok(());
    }

    if dry_run {
        return Ok(());
    }

    let high_risk_count = files_to_apply
        .iter()
        .filter(|change| change.analysis.risk.level == RiskLevel::High)
        .count();

    if high_risk_count > 0 {
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
        ui::info("Use --apply to apply changes non-interactively.");
        false
    };

    let allow_high_risk = if high_risk_count == 0 {
        true
    } else if auto_apply {
        ui::warn("Skipping high-risk changes in --apply mode for safety.");
        false
    } else if std::io::stdin().is_terminal() {
        prompt_apply_high_risk()?
    } else {
        ui::warn("Use interactive mode to apply high-risk changes after review.");
        false
    };

    if should_apply {
        let mut written = 0usize;
        for change in &files_to_apply {
            if change.analysis.risk.level == RiskLevel::High && !allow_high_risk {
                ui::warn(&format!(
                    "Skipped high-risk change: {}",
                    change.file.display_path
                ));
                continue;
            }

            std::fs::write(&change.file.path, &change.content)?;
            ui::info(&format!("Written: {}", change.file.display_path));
            written += 1;
        }

        if written == 0 {
            ui::warn("No files were written.");
        } else {
            let repo_config = seed_repo_config_from_files(&files)?;
            ui::blank_line();
            if let Some(result) = &repo_config {
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

    Ok(())
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

    scan_dockerfiles_recursively(&cwd, &mut files);

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

fn scan_dockerfiles_recursively(root: &Path, files: &mut Vec<ScannedFile>) {
    for entry in WalkDir::new(root) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        if entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };

        if name != "Dockerfile"
            && !name.starts_with("Dockerfile.")
            && !name.ends_with(".dockerfile")
        {
            continue;
        }

        let display = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();

        if let Some(file) = try_read_file(&path, &display) {
            files.push(file);
        }
    }
}

fn scan_exact(root: &Path, relative: &str, files: &mut Vec<ScannedFile>) {
    let path = root.join(relative);
    if let Some(file) = try_read_file(&path, relative) {
        files.push(file);
    }
}

fn scan_glob(root: &Path, dir: &str, extensions: &[&str], files: &mut Vec<ScannedFile>) {
    let dir_path = root.join(dir);
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
) -> Result<String> {
    let client = ApiClient::new()?;
    let connect = client.create_cli_connect_session().await?;
    let verification_url_with_code = format!(
        "{}?code={}",
        connect.verification_url,
        urlencoding::encode(&connect.user_code)
    );

    ui::blank_line();
    let email_auth_selected = email_auth.is_some();

    if let Some(email_auth) = email_auth {
        ui::info("Continue onboarding by email:");
        ui::info(&format!("  Email: {}", email_auth.email));
        ui::info(&format!("  Browser fallback: {}", connect.authorize_url));
        start_cli_connect_email_auth(&client, &connect.session_id, email_auth).await?;
    } else {
        ui::info("Approve CLI access:");
        ui::info(&format!("  1. Open {}", connect.verification_url));
        ui::info(&format!("  2. Enter code {}", connect.user_code));
        ui::info(&format!("  Direct link: {}", connect.authorize_url));

        if !manual && try_open_browser(&verification_url_with_code) {
            ui::info("Opened verification page automatically.");
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
mod tests {
    use super::*;

    #[test]
    fn try_read_file_skips_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.yml");
        std::fs::write(&path, "hello\0world").unwrap();
        assert!(try_read_file(&path, "test.yml").is_none());
    }

    #[test]
    fn try_read_file_reads_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ci.yml");
        std::fs::write(
            &path,
            "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu\n    steps:\n      - run: npm ci",
        )
        .unwrap();

        let file = try_read_file(&path, ".github/workflows/ci.yml").unwrap();
        assert_eq!(file.ci_type, CiType::GitHubActions);
        assert_eq!(file.relevance, FileRelevance::NoCaching);
    }

    #[test]
    fn ci_type_api_keys() {
        assert_eq!(CiType::GitHubActions.api_key(), Some("github_actions"));
        assert_eq!(CiType::Dockerfile.api_key(), Some("dockerfile"));
        assert_eq!(CiType::Unknown.api_key(), None);
    }

    #[test]
    fn relevance_should_send() {
        assert!(FileRelevance::HasCaching.should_send());
        assert!(FileRelevance::NoCaching.should_send());
        assert!(!FileRelevance::AlreadyOptimized.should_send());
        assert!(!FileRelevance::NoOpportunity.should_send());
        assert!(!FileRelevance::TooLarge.should_send());
    }

    #[test]
    fn max_content_length_constant_is_stable() {
        assert_eq!(crate::optimize::MAX_CONTENT_LENGTH, 50_000);
    }

    #[test]
    fn extract_cache_paths_handles_entries_and_cli_specs() {
        let content = r#"
- uses: boringcache/one@v1
  with:
    entries: deps:node_modules,build:dist
- run: boringcache save my-org/app "gems:vendor/bundle"
"#;

        let paths = extract_cache_paths(content);
        assert!(paths.contains(&"node_modules".to_string()));
        assert!(paths.contains(&"dist".to_string()));
        assert!(paths.contains(&"vendor/bundle".to_string()));
    }

    #[test]
    fn assess_cache_risk_flags_sensitive_paths() {
        let paths = vec!["node_modules".to_string(), ".aws/credentials".to_string()];
        let report = assess_cache_risk(&paths);
        assert_eq!(report.level, RiskLevel::High);
        assert_eq!(report.paths, vec![".aws/credentials".to_string()]);
    }

    #[test]
    fn estimate_savings_uses_cache_baseline_when_existing_cache_detected() {
        let original = r#"
steps:
  - uses: actions/cache@v4
    with:
      path: node_modules
"#;
        let paths = vec!["node_modules".to_string()];
        let estimate = estimate_savings(original, CiType::GitHubActions, &paths);
        assert_eq!(estimate.baseline, "current cache baseline");
        assert!(estimate.max_percent <= 28);
    }

    #[test]
    fn estimate_savings_no_cache_baseline_has_higher_upper_bound() {
        let original = "steps:\n  - run: npm ci\n";
        let paths = vec!["node_modules".to_string()];
        let estimate = estimate_savings(original, CiType::GitHubActions, &paths);
        assert_eq!(estimate.baseline, "no cache baseline");
        assert!(estimate.max_percent >= 19);
    }

    #[test]
    fn parse_cli_connect_expiry_parses_rfc3339() {
        let parsed = parse_cli_connect_expiry("2026-03-02T12:00:00Z");
        assert!(parsed.is_some());
    }

    #[test]
    fn parse_cli_connect_expiry_rejects_invalid() {
        let parsed = parse_cli_connect_expiry("not-a-time");
        assert!(parsed.is_none());
    }
}

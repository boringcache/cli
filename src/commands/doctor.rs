use crate::api::{ApiClient, models::SessionInfo};
use crate::config::{
    AuthPurpose, ValueSource, api_url_source, default_workspace_source, token_source_for,
};
use crate::exit_code::ExitCodeError;
use crate::ui;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    ok: bool,
    failure_count: usize,
    warning_count: usize,
    api: ApiReport,
    workspace: WorkspaceReport,
    auth: AuthReport,
    commands: CommandReport,
}

#[derive(Debug, Serialize)]
struct ApiReport {
    configured_url: String,
    source: ValueSource,
    v1_url: String,
    v2_url: String,
}

#[derive(Debug, Serialize)]
struct WorkspaceReport {
    status: DoctorStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved: Option<String>,
    source: ValueSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessible_total: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    accessible_sample: Vec<String>,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthReport {
    restore: PurposeCheck,
    save: PurposeCheck,
    admin: PurposeCheck,
}

#[derive(Debug, Serialize)]
struct PurposeCheck {
    status: DoctorStatus,
    usable: bool,
    source: ValueSource,
    configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_access_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    write_tag_prefixes: Vec<String>,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommandReport {
    status: CommandCheck,
    inspect: CommandCheck,
    save: CommandCheck,
    rm: CommandCheck,
    use_command: CommandCheck,
    workspaces: CommandCheck,
}

#[derive(Debug, Serialize)]
struct CommandCheck {
    status: DoctorStatus,
    ready: bool,
    summary: String,
}

struct PurposeProbe {
    report: PurposeCheck,
    session: Option<SessionInfo>,
    client: Option<ApiClient>,
}

struct WorkspaceProbe {
    report: WorkspaceReport,
    list_status: DoctorStatus,
}

pub async fn execute(workspace: Option<String>, json_output: bool) -> Result<()> {
    let restore = collect_purpose(AuthPurpose::Restore).await;
    let save = collect_purpose(AuthPurpose::Save).await;
    let admin = collect_purpose(AuthPurpose::Admin).await;
    let workspace_probe = collect_workspace(workspace, &restore).await;

    let configured_url = crate::config::Config::get_api_url(None).unwrap_or_default();
    let (v1_url, v2_url) = crate::api::client::derive_api_base_urls(&configured_url);
    let api = ApiReport {
        configured_url,
        source: api_url_source(),
        v1_url,
        v2_url,
    };

    let commands = CommandReport {
        status: command_from_dependencies(
            "Ready for workspace-scoped read checks.",
            "Need a readable workspace to run `status`.",
            &[restore.report.status, workspace_probe.report.status],
        ),
        inspect: command_from_dependencies(
            "Ready for cache inspection.",
            "Need a readable workspace to run `inspect`.",
            &[restore.report.status, workspace_probe.report.status],
        ),
        save: command_from_dependencies(
            "Ready for cache saves.",
            "Need a save-capable token and workspace to run `save`.",
            &[save.report.status, workspace_probe.report.status],
        ),
        rm: command_from_dependencies(
            "Ready for cache deletion.",
            "Need an admin-capable token and workspace to run `rm`.",
            &[admin.report.status, workspace_probe.report.status],
        ),
        use_command: command_from_dependencies(
            "Ready to choose a saved default workspace.",
            "Need a readable token and working workspace discovery to run `use`.",
            &[restore.report.status, workspace_probe.list_status],
        ),
        workspaces: command_from_dependencies(
            "Ready to list accessible workspaces.",
            "Need a readable token and working workspace discovery to run `workspaces`.",
            &[restore.report.status, workspace_probe.list_status],
        ),
    };

    let report = DoctorReport {
        ok: true,
        failure_count: 0,
        warning_count: 0,
        api,
        workspace: workspace_probe.report,
        auth: AuthReport {
            restore: restore.report,
            save: save.report,
            admin: admin.report,
        },
        commands,
    };

    let report = finalize_report(report);

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if report.ok {
            return Ok(());
        }
        return Err(ExitCodeError::silent(1).into());
    }

    render_report(&report);
    if report.ok {
        return Ok(());
    }

    Err(ExitCodeError::with_message(
        1,
        "Doctor found configuration issues. Use `boringcache doctor --json` in CI for machine-readable checks.",
    )
    .into())
}

async fn collect_purpose(purpose: AuthPurpose) -> PurposeProbe {
    let source = token_source_for(purpose);
    if source.is_missing() {
        return PurposeProbe {
            report: PurposeCheck {
                status: DoctorStatus::Warn,
                usable: false,
                configured: false,
                source,
                actual_access_level: None,
                scope_type: None,
                workspace_slug: None,
                organization_slug: None,
                write_tag_prefixes: Vec::new(),
                summary: format!(
                    "No {} token configured.",
                    purpose_name(purpose).to_lowercase()
                ),
                error: None,
            },
            session: None,
            client: None,
        };
    }

    let client = match ApiClient::new_for_purpose(purpose) {
        Ok(client) => client,
        Err(err) => {
            return PurposeProbe {
                report: PurposeCheck {
                    status: DoctorStatus::Fail,
                    usable: false,
                    configured: true,
                    source,
                    actual_access_level: None,
                    scope_type: None,
                    workspace_slug: None,
                    organization_slug: None,
                    write_tag_prefixes: Vec::new(),
                    summary: format!("{} token could not be loaded.", purpose_name(purpose)),
                    error: Some(err.to_string()),
                },
                session: None,
                client: None,
            };
        }
    };

    match client.get_session_info().await {
        Ok(session) => {
            let usable = session.valid
                && access_level_supports_purpose(&session.token.access_level, purpose);
            let status = if usable {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Fail
            };
            let summary = if usable {
                format!(
                    "Authenticated as {} with {} scope.",
                    session.token.access_level, session.token.scope_type
                )
            } else if session.token.access_level.is_empty() {
                "Authenticated token did not report an access level.".to_string()
            } else {
                format!(
                    "Authenticated as {}, which is not enough for {}.",
                    session.token.access_level,
                    purpose_name(purpose).to_lowercase()
                )
            };

            let workspace_slug = session
                .workspace
                .as_ref()
                .and_then(|workspace| workspace.slug.clone());
            let organization_slug = session
                .organization
                .as_ref()
                .and_then(|organization| organization.slug.clone());

            PurposeProbe {
                report: PurposeCheck {
                    status,
                    usable,
                    configured: true,
                    source,
                    actual_access_level: Some(session.token.access_level.clone()),
                    scope_type: Some(session.token.scope_type.clone()),
                    workspace_slug,
                    organization_slug,
                    write_tag_prefixes: session.token.write_tag_prefixes.clone(),
                    summary,
                    error: None,
                },
                session: Some(session),
                client: Some(client),
            }
        }
        Err(err) => PurposeProbe {
            report: PurposeCheck {
                status: DoctorStatus::Fail,
                usable: false,
                configured: true,
                source,
                actual_access_level: None,
                scope_type: None,
                workspace_slug: None,
                organization_slug: None,
                write_tag_prefixes: Vec::new(),
                summary: format!(
                    "{} token could not authenticate against the API.",
                    purpose_name(purpose)
                ),
                error: Some(err.to_string()),
            },
            session: None,
            client: None,
        },
    }
}

async fn collect_workspace(requested: Option<String>, restore: &PurposeProbe) -> WorkspaceProbe {
    let requested = requested
        .map(|workspace| workspace.trim().to_string())
        .filter(|workspace| !workspace.is_empty());
    let configured_workspace = crate::command_support::configured_workspace();
    let session_workspace = restore
        .session
        .as_ref()
        .and_then(|session| session.workspace.as_ref())
        .and_then(|workspace| workspace.slug.clone());

    let (accessible_total, accessible_sample, accessible_all, list_status, list_error) =
        if let Some(client) = restore.client.as_ref() {
            match client.list_workspaces().await {
                Ok(mut workspaces) => {
                    workspaces.sort_by(|a, b| a.slug.cmp(&b.slug));
                    let sample = workspaces
                        .iter()
                        .take(5)
                        .map(|workspace| workspace.slug.clone())
                        .collect::<Vec<_>>();
                    let all = workspaces
                        .into_iter()
                        .map(|workspace| workspace.slug)
                        .collect::<Vec<_>>();
                    (Some(all.len()), sample, Some(all), DoctorStatus::Ok, None)
                }
                Err(err) => (
                    None,
                    Vec::new(),
                    None,
                    DoctorStatus::Fail,
                    Some(err.to_string()),
                ),
            }
        } else if restore.report.status == DoctorStatus::Warn {
            (None, Vec::new(), None, DoctorStatus::Warn, None)
        } else {
            (
                None,
                Vec::new(),
                None,
                DoctorStatus::Fail,
                restore.report.error.clone(),
            )
        };

    let scoped_workspace = if let Some(raw_workspace) = session_workspace.as_ref() {
        if raw_workspace.contains('/') {
            Some(raw_workspace.clone())
        } else if let Some(workspaces) = accessible_all.as_ref() {
            let matches = workspaces
                .iter()
                .filter(|candidate| {
                    candidate
                        .rsplit('/')
                        .next()
                        .is_some_and(|slug| slug == raw_workspace)
                })
                .cloned()
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0].clone())
        } else {
            None
        }
    } else {
        None
    };

    let (resolved, source) = if let Some(workspace) = requested.clone() {
        (
            Some(workspace.clone()),
            ValueSource {
                kind: "explicit".to_string(),
                detail: Some(workspace),
            },
        )
    } else if let Some(workspace) = configured_workspace {
        (Some(workspace), default_workspace_source())
    } else if let Some(workspace) = scoped_workspace.clone() {
        (
            Some(workspace.clone()),
            ValueSource {
                kind: "token_scope".to_string(),
                detail: Some(workspace),
            },
        )
    } else if let Some(workspaces) = accessible_all.as_ref() {
        if workspaces.len() == 1 {
            (
                Some(workspaces[0].clone()),
                ValueSource {
                    kind: "inferred_single_workspace".to_string(),
                    detail: Some(workspaces[0].clone()),
                },
            )
        } else {
            (
                None,
                ValueSource {
                    kind: "missing".to_string(),
                    detail: None,
                },
            )
        }
    } else {
        (
            None,
            ValueSource {
                kind: "missing".to_string(),
                detail: None,
            },
        )
    };

    let accessible = if let Some(workspace) = resolved.as_ref() {
        accessible_all
            .as_ref()
            .map(|workspaces| workspaces.iter().any(|candidate| candidate == workspace))
            .or_else(|| {
                scoped_workspace
                    .as_ref()
                    .map(|scoped_workspace| scoped_workspace == workspace)
            })
    } else {
        None
    };

    let mismatch_with_scoped_token = resolved.as_ref().is_some_and(|workspace| {
        scoped_workspace
            .as_ref()
            .is_some_and(|scoped_workspace| scoped_workspace != workspace)
    });

    let (status, summary, error) = if let Some(workspace) = resolved.as_ref() {
        if accessible == Some(false) || mismatch_with_scoped_token {
            (
                DoctorStatus::Fail,
                format!(
                    "Workspace '{workspace}' is not accessible with the current readable token."
                ),
                Some(
                    "Run `boringcache use` with an accessible workspace or switch tokens."
                        .to_string(),
                ),
            )
        } else {
            (
                DoctorStatus::Ok,
                format!("Resolved workspace '{workspace}'."),
                list_error.clone(),
            )
        }
    } else if accessible_total == Some(0) {
        (
            DoctorStatus::Fail,
            "No accessible workspaces found for the current token.".to_string(),
            list_error.clone(),
        )
    } else if accessible_total.unwrap_or_default() > 1 {
        (
            DoctorStatus::Warn,
            "No default workspace is set. Pick one with `boringcache use` or pass a workspace explicitly.".to_string(),
            list_error.clone(),
        )
    } else if list_status == DoctorStatus::Fail {
        (
            DoctorStatus::Fail,
            "Could not resolve a workspace automatically.".to_string(),
            list_error.clone(),
        )
    } else {
        (
            DoctorStatus::Warn,
            "No default workspace is set yet.".to_string(),
            list_error.clone(),
        )
    };

    WorkspaceProbe {
        report: WorkspaceReport {
            status,
            requested,
            resolved,
            source,
            accessible_total,
            accessible_sample,
            summary,
            error,
        },
        list_status,
    }
}

fn finalize_report(mut report: DoctorReport) -> DoctorReport {
    let statuses = [
        report.workspace.status,
        report.auth.restore.status,
        report.auth.save.status,
        report.auth.admin.status,
        report.commands.status.status,
        report.commands.inspect.status,
        report.commands.save.status,
        report.commands.rm.status,
        report.commands.use_command.status,
        report.commands.workspaces.status,
    ];

    report.failure_count = statuses
        .iter()
        .filter(|status| **status == DoctorStatus::Fail)
        .count();
    report.warning_count = statuses
        .iter()
        .filter(|status| **status == DoctorStatus::Warn)
        .count();
    report.ok = report.failure_count == 0;
    report
}

fn command_from_dependencies(
    ok_summary: &str,
    blocked_summary: &str,
    statuses: &[DoctorStatus],
) -> CommandCheck {
    let status = statuses.iter().copied().max().unwrap_or(DoctorStatus::Ok);

    CommandCheck {
        status,
        ready: status == DoctorStatus::Ok,
        summary: if status == DoctorStatus::Ok {
            ok_summary.to_string()
        } else {
            blocked_summary.to_string()
        },
    }
}

fn render_report(report: &DoctorReport) {
    ui::blank_line();
    println!("API");
    print_field("URL", &report.api.configured_url);
    print_field("Source", &format_source(&report.api.source));
    print_field("v1", &report.api.v1_url);
    print_field("v2", &report.api.v2_url);
    ui::blank_line();

    println!("Workspace");
    print_field("Status", status_label(report.workspace.status));
    print_field(
        "Resolved",
        report
            .workspace
            .resolved
            .as_deref()
            .unwrap_or("(not resolved)"),
    );
    print_field("Source", &format_source(&report.workspace.source));
    if let Some(total) = report.workspace.accessible_total {
        print_field("Accessible", &total.to_string());
    }
    if !report.workspace.accessible_sample.is_empty() {
        print_field("Sample", &report.workspace.accessible_sample.join(", "));
    }
    print_field("Summary", &report.workspace.summary);
    if let Some(error) = report.workspace.error.as_deref() {
        print_field("Error", error);
    }
    ui::blank_line();

    println!("Auth");
    render_purpose("Restore", &report.auth.restore);
    render_purpose("Save", &report.auth.save);
    render_purpose("Admin", &report.auth.admin);
    ui::blank_line();

    println!("Commands");
    render_command("status", &report.commands.status);
    render_command("inspect", &report.commands.inspect);
    render_command("save", &report.commands.save);
    render_command("rm", &report.commands.rm);
    render_command("use", &report.commands.use_command);
    render_command("workspaces", &report.commands.workspaces);
    ui::blank_line();

    if report.ok {
        ui::info("Doctor check passed.");
    } else {
        ui::warn(&format!(
            "Doctor found {} failure(s) and {} warning(s).",
            report.failure_count, report.warning_count
        ));
    }
}

fn render_purpose(label: &str, check: &PurposeCheck) {
    println!(
        "  {:<10} {:<4} {}",
        label,
        status_label(check.status),
        check.summary
    );
    print_field("  source", &format_source(&check.source));
    if let Some(access_level) = check.actual_access_level.as_deref() {
        print_field("  access", access_level);
    }
    if let Some(scope_type) = check.scope_type.as_deref() {
        print_field("  scope", scope_type);
    }
    if let Some(workspace_slug) = check.workspace_slug.as_deref() {
        print_field("  workspace", workspace_slug);
    }
    if let Some(organization_slug) = check.organization_slug.as_deref() {
        print_field("  org", organization_slug);
    }
    if !check.write_tag_prefixes.is_empty() {
        print_field("  prefixes", &check.write_tag_prefixes.join(", "));
    }
    if let Some(error) = check.error.as_deref() {
        print_field("  error", error);
    }
}

fn render_command(label: &str, check: &CommandCheck) {
    println!(
        "  {:<10} {:<4} {}",
        label,
        status_label(check.status),
        check.summary
    );
}

fn print_field(label: &str, value: &str) {
    println!("  {:<11} {}", label, value);
}

fn format_source(source: &ValueSource) -> String {
    match source.detail.as_deref() {
        Some(detail) => format!("{} ({detail})", source.kind),
        None => source.kind.clone(),
    }
}

fn status_label(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Ok => "ok",
        DoctorStatus::Warn => "warn",
        DoctorStatus::Fail => "fail",
    }
}

fn purpose_name(purpose: AuthPurpose) -> &'static str {
    match purpose {
        AuthPurpose::Default => "Default",
        AuthPurpose::Restore => "Restore",
        AuthPurpose::Save => "Save",
        AuthPurpose::Admin => "Admin",
    }
}

fn access_level_supports_purpose(access_level: &str, purpose: AuthPurpose) -> bool {
    let required = match purpose {
        AuthPurpose::Default | AuthPurpose::Restore => 0,
        AuthPurpose::Save => 1,
        AuthPurpose::Admin => 2,
    };

    let actual = match access_level {
        "restore" => 0,
        "save" => 1,
        "admin" => 2,
        _ => -1,
    };

    actual >= required
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_level_hierarchy_matches_expected() {
        assert!(access_level_supports_purpose(
            "restore",
            AuthPurpose::Restore
        ));
        assert!(access_level_supports_purpose("save", AuthPurpose::Restore));
        assert!(access_level_supports_purpose("admin", AuthPurpose::Restore));
        assert!(!access_level_supports_purpose("restore", AuthPurpose::Save));
        assert!(access_level_supports_purpose("save", AuthPurpose::Save));
        assert!(access_level_supports_purpose("admin", AuthPurpose::Save));
        assert!(!access_level_supports_purpose("save", AuthPurpose::Admin));
        assert!(access_level_supports_purpose("admin", AuthPurpose::Admin));
    }

    #[test]
    fn command_readiness_follows_highest_dependency_status() {
        let check =
            command_from_dependencies("ready", "blocked", &[DoctorStatus::Ok, DoctorStatus::Warn]);
        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(!check.ready);
        assert_eq!(check.summary, "blocked");
    }
}

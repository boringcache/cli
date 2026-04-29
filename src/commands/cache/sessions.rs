use crate::api::{ApiClient, models::workspace::WorkspaceSessionsResponse};
use anyhow::Result;

pub async fn execute(
    workspace_option: Option<String>,
    period: String,
    limit: u32,
    page: u32,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_restore()?;
    let workspace = crate::command_support::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache sessions <workspace>",
    )
    .await?;
    let offset = (page.saturating_sub(1)).saturating_mul(limit);
    let response = api_client
        .workspace_sessions(&workspace, &period, limit, offset)
        .await?;

    if json_output {
        crate::json_output::print(&response)?;
        return Ok(());
    }

    render_sessions_report(&response);
    Ok(())
}

fn render_sessions_report(response: &WorkspaceSessionsResponse) {
    crate::ui::blank_line();
    println!("Sessions");
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    crate::commands::status::print_field("Period", &format!("last {}", response.period.key));
    crate::commands::status::print_field("Showing", &showing_range(&response.pagination));
    crate::commands::status::print_field(
        "Summary",
        &format!(
            "{} total, {} healthy, {} errors",
            response.session_health.total_sessions,
            response.session_health.healthy_sessions,
            response.session_health.error_sessions
        ),
    );
    crate::ui::blank_line();

    if response.sessions.is_empty() {
        println!("  none");
        return;
    }

    for session in &response.sessions {
        println!(
            "  {:<12} {:>6} hit  {:>8}  {}",
            session.tool,
            crate::commands::status::format_percent(session.hit_rate),
            crate::commands::status::format_duration_seconds(session.duration_seconds),
            crate::commands::status::format_relative_time(&session.created_at)
        );
        println!(
            "    counts: {} hits, {} misses, {} errors",
            session.hit_count, session.miss_count, session.error_count
        );
        println!(
            "    traffic: {} read, {} written",
            crate::progress::format_bytes(session.bytes_read),
            crate::progress::format_bytes(session.bytes_written)
        );

        let mut context = Vec::new();
        if let Some(project) = session.project_hint.as_deref() {
            context.push(format!("project:{project}"));
        }
        if let Some(phase) = session.phase_hint.as_deref() {
            context.push(format!("phase:{phase}"));
        }
        for (key, value) in &session.metadata_hints {
            if key == "project" || key == "phase" {
                continue;
            }
            context.push(format!("{key}:{value}"));
        }
        if !context.is_empty() {
            println!(
                "    context: {}",
                crate::commands::status::truncate(&context.join(" "), 80)
            );
        }

        for line in crate::commands::status::session_review_lines(session) {
            println!("    {line}");
        }

        if !session.missed_keys.is_empty() {
            let misses = session
                .missed_keys
                .iter()
                .map(|entry| {
                    entry
                        .sampled_key_prefix
                        .as_deref()
                        .map(|value| crate::commands::status::truncate(value, 36))
                        .unwrap_or_else(|| crate::commands::status::truncate(&entry.key_hash, 18))
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("    missed: {misses}");
        }

        if session.error_count > 0 && !session.error_details.is_empty() {
            let detail = session
                .error_details
                .iter()
                .map(|entry| format!("{} x{}", entry.operation, entry.count))
                .collect::<Vec<_>>()
                .join(", ");
            println!("    errors: {detail}");
        }
    }

    if response.pagination.has_more {
        crate::ui::blank_line();
        println!(
            "Next page: boringcache sessions {} --page {} --limit {}",
            response.workspace.slug,
            response.pagination.offset / response.pagination.limit + 2,
            response.pagination.limit
        );
    }
}

fn showing_range(pagination: &crate::api::models::workspace::WorkspacePagination) -> String {
    if pagination.total == 0 || pagination.returned == 0 {
        return format!("0 of {}", pagination.total);
    }

    format!(
        "{}-{} of {}",
        pagination.offset + 1,
        pagination.offset + pagination.returned,
        pagination.total
    )
}

#[cfg(test)]
mod tests {
    use crate::api::models::workspace::{
        WorkspacePagination, WorkspaceSessionsResponse, WorkspaceStatusPeriod,
        WorkspaceStatusSession, WorkspaceStatusSessionError, WorkspaceStatusSessionHealth,
        WorkspaceStatusSessionMissedKey, WorkspaceStatusWorkspace,
    };
    use serde_json::Value;

    #[test]
    fn sessions_json_contract_adds_schema_version() {
        let response = WorkspaceSessionsResponse {
            workspace: WorkspaceStatusWorkspace {
                id: Value::String("ws_1".to_string()),
                name: "Demo".to_string(),
                slug: "org/demo".to_string(),
                description: None,
                provisioned: true,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                updated_at: "2026-04-15T00:00:00Z".to_string(),
            },
            period: WorkspaceStatusPeriod {
                key: "24h".to_string(),
                started_at: "2026-04-14T00:00:00Z".to_string(),
                ended_at: "2026-04-15T00:00:00Z".to_string(),
            },
            generated_at: "2026-04-15T00:00:00Z".to_string(),
            session_health: WorkspaceStatusSessionHealth {
                total_sessions: 1,
                healthy_sessions: 1,
                error_sessions: 0,
                degraded_sessions: 0,
                avg_hit_rate: 0.8,
                avg_duration_ms: 3000.0,
            },
            pagination: WorkspacePagination {
                limit: 20,
                offset: 0,
                total: 1,
                returned: 1,
                has_more: false,
            },
            sessions: vec![WorkspaceStatusSession {
                session_id: "sess_1".to_string(),
                tool: "turbo".to_string(),
                project_hint: Some("demo".to_string()),
                phase_hint: Some("build".to_string()),
                metadata_hints: std::collections::BTreeMap::new(),
                hit_rate: 0.8,
                hit_count: 8,
                miss_count: 2,
                error_count: 0,
                error_details: vec![WorkspaceStatusSessionError {
                    operation: "get".to_string(),
                    count: 0,
                }],
                duration_seconds: Some(3.0),
                bytes_read: 512,
                bytes_written: 256,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                missed_keys: vec![WorkspaceStatusSessionMissedKey {
                    key_hash: "abc123".to_string(),
                    miss_count: 2,
                    sampled_key_prefix: Some("deps-".to_string()),
                }],
                review: None,
            }],
        };

        let value = crate::json_output::to_value(&response).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["workspace"]["slug"], "org/demo");
        assert_eq!(value["sessions"][0]["tool"], "turbo");
    }
}

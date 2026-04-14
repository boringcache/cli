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
        println!("{}", serde_json::to_string_pretty(&response)?);
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

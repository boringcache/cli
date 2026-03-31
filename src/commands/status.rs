use crate::api::{ApiClient, models::workspace::WorkspaceStatusResponse};
use crate::progress::format_bytes;
use crate::ui;
use anyhow::Result;
use chrono::{DateTime, Utc};

pub async fn execute(
    workspace_option: Option<String>,
    period: String,
    limit: u32,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_restore()?;
    let workspace = crate::commands::utils::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache status <workspace>",
    )
    .await?;
    let status = api_client
        .workspace_status(&workspace, &period, limit)
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    render_status(&status);
    Ok(())
}

fn render_status(status: &WorkspaceStatusResponse) {
    ui::blank_line();
    print_header(status);
    print_inventory(status);
    print_operations(status);
    print_savings(status);
    print_tools(status);
    print_sessions(status);
    print_missed_keys(status);
}

fn print_header(status: &WorkspaceStatusResponse) {
    println!("Workspace");
    print_field("Slug", &status.workspace.slug);
    print_field("Name", &status.workspace.name);
    print_field("Period", &format!("last {}", status.period.key));
    print_field(
        "Provisioned",
        if status.workspace.provisioned {
            "yes"
        } else {
            "no"
        },
    );
    print_field("Generated", &format_relative_time(&status.generated_at));
    if let Some(description) = status.workspace.description.as_deref()
        && !description.trim().is_empty()
    {
        print_field("Description", description);
    }
    ui::blank_line();
}

fn print_inventory(status: &WorkspaceStatusResponse) {
    println!("Inventory");
    print_field(
        "Tagged entries",
        &status.inventory.tagged_entries_count.to_string(),
    );
    print_field(
        "Stored",
        &format_bytes(status.inventory.tagged_storage_bytes),
    );
    print_field("Tag hits", &status.inventory.tagged_hits.to_string());
    print_field("Versions", &status.inventory.version_count.to_string());
    print_field(
        "Orphaned",
        &format!(
            "{} ({})",
            status.inventory.orphaned_entries_count,
            format_bytes(status.inventory.orphaned_storage_bytes)
        ),
    );
    print_field(
        "Dedup saved",
        &format!(
            "{} ({})",
            format_bytes(status.inventory.dedup_savings_bytes),
            format_percent(status.inventory.dedup_ratio)
        ),
    );
    ui::blank_line();
}

fn print_operations(status: &WorkspaceStatusResponse) {
    println!("Operations");
    print_field(
        "Requests",
        &status.operations.cache.total_requests.to_string(),
    );
    print_field(
        "Hits",
        &format!(
            "{} ({})",
            status.operations.cache.total_hits,
            format_percent(status.operations.cache.hit_rate)
        ),
    );
    print_field("Served", &format_bytes(status.savings.bytes_served));
    print_field(
        "Avg latency",
        &format_millis(status.operations.cache.avg_latency_ms),
    );
    print_field(
        "Warm hit rate",
        &format_percent(status.operations.cache_health.warm_hit_rate),
    );
    print_field(
        "Misses",
        &format!(
            "{} total, {} recurring, {} cold",
            status.operations.cache_health.total_misses,
            status.operations.cache_health.recurring_misses,
            status.operations.cache_health.cold_misses
        ),
    );
    print_field(
        "Degraded",
        &format!(
            "{} cache, {} runtime",
            status.operations.cache.degraded_count, status.operations.runtime.degraded_count
        ),
    );
    print_field(
        "Sessions",
        &format!(
            "{} total, {} healthy, {} errors",
            status.operations.session_health.total_sessions,
            status.operations.session_health.healthy_sessions,
            status.operations.session_health.error_sessions
        ),
    );
    print_field(
        "Avg session",
        &format!(
            "{} at {} hit rate",
            format_duration_seconds(Some(
                status.operations.session_health.avg_duration_ms / 1000.0
            )),
            format_percent(status.operations.session_health.avg_hit_rate)
        ),
    );
    ui::blank_line();
}

fn print_savings(status: &WorkspaceStatusResponse) {
    println!("Savings");
    print_field("Restores", &status.savings.cli_restores.to_string());
    print_field("Bytes served", &format_bytes(status.savings.bytes_served));
    print_field("Bytes written", &format_bytes(status.savings.bytes_written));
    print_field(
        "Compression",
        &format!(
            "{} saved, avg restore {}",
            format_bytes(status.savings.cli_compression_saved),
            format_millis(status.savings.cli_avg_restore_ms)
        ),
    );
    print_field(
        "Dedup saved",
        &format!(
            "{} ({})",
            format_bytes(status.savings.dedup_savings_bytes),
            format_percent(status.savings.dedup_ratio)
        ),
    );
    ui::blank_line();
}

fn print_tools(status: &WorkspaceStatusResponse) {
    println!("Top tools");

    if status.tools.is_empty() {
        println!("  none");
        ui::blank_line();
        return;
    }

    for tool in &status.tools {
        println!(
            "  {:<12} {:>6} lookups  {:>6} hit  {:>10} served",
            tool.tool,
            tool.lookup_total,
            format_percent(tool.hit_rate),
            format_bytes(tool.bytes_total)
        );
    }

    ui::blank_line();
}

fn print_sessions(status: &WorkspaceStatusResponse) {
    println!("Recent sessions");

    if status.sessions.is_empty() {
        println!("  none");
        ui::blank_line();
        return;
    }

    for session in &status.sessions {
        println!(
            "  {:<12} {:>6} hit  {:>8}  {}",
            session.tool,
            format_percent(session.hit_rate),
            format_duration_seconds(session.duration_seconds),
            format_relative_time(&session.created_at)
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
            println!("    context: {}", truncate(&context.join(" "), 80));
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

    ui::blank_line();
}

fn print_missed_keys(status: &WorkspaceStatusResponse) {
    println!("Hot misses");

    if status.missed_keys.is_empty() {
        println!("  none");
        return;
    }

    for missed_key in &status.missed_keys {
        let prefix = missed_key
            .sampled_key_prefix
            .as_deref()
            .map(|value| truncate(value, 44))
            .unwrap_or_else(|| missed_key.key_hash.chars().take(12).collect());
        let seen = missed_key
            .last_seen_at
            .as_deref()
            .map(format_relative_time)
            .unwrap_or_else(|| "unknown".to_string());

        println!(
            "  {:<12} {:>4} misses  {:<9}  {}",
            missed_key.tool,
            missed_key.miss_count,
            format!("({})", missed_key.miss_state),
            seen
        );
        println!("    {prefix}");
    }
}

fn print_field(label: &str, value: &str) {
    println!("  {label:<12} {value}");
}

fn format_percent(value: f64) -> String {
    format!("{value:.1}%")
}

fn format_millis(value: f64) -> String {
    if value >= 1000.0 {
        format_duration_seconds(Some(value / 1000.0))
    } else {
        format!("{:.0}ms", value)
    }
}

fn format_duration_seconds(value: Option<f64>) -> String {
    let Some(seconds) = value else {
        return "-".to_string();
    };

    if seconds >= 3600.0 {
        format!("{:.1}h", seconds / 3600.0)
    } else if seconds >= 60.0 {
        format!("{:.1}m", seconds / 60.0)
    } else if seconds >= 1.0 {
        format!("{seconds:.0}s")
    } else {
        "<1s".to_string()
    }
}

fn format_relative_time(timestamp: &str) -> String {
    let Ok(parsed) = DateTime::parse_from_rfc3339(timestamp) else {
        return timestamp.to_string();
    };

    let now = Utc::now();
    let diff = now.signed_duration_since(parsed.with_timezone(&Utc));

    if diff.num_days() > 0 {
        format!("{} days ago", diff.num_days())
    } else if diff.num_hours() > 0 {
        format!("{} hours ago", diff.num_hours())
    } else if diff.num_minutes() > 0 {
        format!("{} minutes ago", diff.num_minutes())
    } else {
        "just now".to_string()
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }

    let mut truncated = value
        .chars()
        .take(max_len.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_seconds_formats_ranges() {
        assert_eq!(format_duration_seconds(Some(0.2)), "<1s");
        assert_eq!(format_duration_seconds(Some(5.0)), "5s");
        assert_eq!(format_duration_seconds(Some(90.0)), "1.5m");
    }

    #[test]
    fn truncate_shortens_long_values() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
        assert_eq!(truncate("short", 10), "short");
    }
}

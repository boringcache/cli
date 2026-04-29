use crate::api::{
    ApiClient,
    models::workspace::{WorkspaceStatusResponse, WorkspaceStatusSession},
};
use crate::progress::format_bytes;
use crate::ui;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::io::{IsTerminal, Write};
use std::time::Duration;

pub async fn execute(
    workspace_option: Option<String>,
    period: String,
    limit: u32,
    watch: bool,
    interval_seconds: u64,
    json_output: bool,
) -> Result<()> {
    let (api_client, workspace) =
        resolve_status_target(workspace_option, "boringcache status <workspace>").await?;

    if watch {
        return watch_status(&api_client, &workspace, &period, limit, interval_seconds).await;
    }

    let status = api_client
        .workspace_status(&workspace, &period, limit)
        .await?;
    if json_output {
        crate::json_output::print(&status)?;
        return Ok(());
    }

    render_status(&status);
    Ok(())
}

pub(crate) fn render_status(status: &WorkspaceStatusResponse) {
    ui::blank_line();
    print_header(status);
    print_inventory(status);
    print_operations(status);
    print_savings(status);
    print_tools(status);
    print_sessions_section(status);
    print_missed_keys_section(status);
}

async fn resolve_status_target(
    workspace_option: Option<String>,
    explicit_example: &str,
) -> Result<(ApiClient, String)> {
    let api_client = ApiClient::for_restore()?;
    let workspace =
        crate::command_support::resolve_workspace(&api_client, workspace_option, explicit_example)
            .await?;
    Ok((api_client, workspace))
}

async fn watch_status(
    api_client: &ApiClient,
    workspace: &str,
    period: &str,
    limit: u32,
    interval_seconds: u64,
) -> Result<()> {
    let interactive = std::io::stdout().is_terminal() && std::env::var_os("CI").is_none();
    let mut first_snapshot = true;

    loop {
        let status = api_client
            .workspace_status(workspace, period, limit)
            .await?;
        render_watch_snapshot(&status, interval_seconds, interactive, first_snapshot)?;
        first_snapshot = false;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if interactive {
                    ui::blank_line();
                }
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(interval_seconds)) => {}
        }
    }

    Ok(())
}

fn render_watch_snapshot(
    status: &WorkspaceStatusResponse,
    interval_seconds: u64,
    interactive: bool,
    first_snapshot: bool,
) -> Result<()> {
    if interactive {
        print!("\x1b[2J\x1b[H");
        std::io::stdout().flush()?;
    } else if !first_snapshot {
        println!("\n---");
    }

    println!(
        "Watching workspace status every {}s. Press Ctrl-C to stop.",
        interval_seconds
    );
    render_status(status);
    Ok(())
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
        "Actionable",
        &format!(
            "{} total, {} recurring, {} first-seen",
            status.operations.cache_health.session_miss_total,
            status.operations.cache_health.recurring_misses,
            status.operations.cache_health.cold_misses
        ),
    );
    print_field(
        "Excluded seed",
        &format!(
            "{} across {} labeled sessions",
            status.operations.cache_health.excluded_seed_misses,
            status.operations.cache_health.excluded_seed_sessions
        ),
    );
    print_field(
        "Degraded",
        &format!(
            "{} lookup, {} runtime",
            status.operations.cache_health.degraded_misses,
            status.operations.runtime.degraded_count
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

fn print_sessions_section(status: &WorkspaceStatusResponse) {
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
        println!(
            "    counts: {} hits, {} misses, {} errors",
            session.hit_count, session.miss_count, session.error_count
        );
        println!(
            "    traffic: {} read, {} written",
            format_bytes(session.bytes_read),
            format_bytes(session.bytes_written)
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

        for line in session_review_lines(session) {
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
                        .map(|value| truncate(value, 36))
                        .unwrap_or_else(|| truncate(&entry.key_hash, 18))
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

    ui::blank_line();
}

pub(crate) fn session_review_lines(session: &WorkspaceStatusSession) -> Vec<String> {
    let Some(review) = session.review.as_ref() else {
        return Vec::new();
    };

    if review.state == "clear" && review.issue_candidates.is_empty() && !review.service_side_issue {
        return Vec::new();
    }

    let label = match review.state.as_str() {
        "action_required" => "action",
        "service_side_issue" => "service",
        _ => "review",
    };
    let mut lines = vec![format!(
        "review: {label} - {}",
        truncate(&review.summary, 92)
    )];

    if let Some(action) = review
        .issue_candidates
        .first()
        .and_then(|candidate| candidate.suggested_action.as_deref())
    {
        lines.push(format!("next: {}", truncate(action, 92)));
    }

    lines
}

fn print_missed_keys_section(status: &WorkspaceStatusResponse) {
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

pub(crate) fn print_field(label: &str, value: &str) {
    println!("  {label:<12} {value}");
}

pub(crate) fn format_percent(value: f64) -> String {
    format!("{value:.1}%")
}

pub(crate) fn format_millis(value: f64) -> String {
    if value >= 1000.0 {
        format_duration_seconds(Some(value / 1000.0))
    } else {
        format!("{value:.0}ms")
    }
}

pub(crate) fn format_duration_seconds(value: Option<f64>) -> String {
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

pub(crate) fn format_relative_time(timestamp: &str) -> String {
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

pub(crate) fn truncate(value: &str, max_len: usize) -> String {
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
    use crate::api::models::workspace::{
        WorkspaceStatusCacheHealth, WorkspaceStatusCacheSummary, WorkspaceStatusInventory,
        WorkspaceStatusMissedKey, WorkspaceStatusOperations, WorkspaceStatusPeriod,
        WorkspaceStatusResponse, WorkspaceStatusRuntimeSummary, WorkspaceStatusSavings,
        WorkspaceStatusSession, WorkspaceStatusSessionError, WorkspaceStatusSessionHealth,
        WorkspaceStatusSessionIssueCandidate, WorkspaceStatusSessionMissedKey,
        WorkspaceStatusSessionReview, WorkspaceStatusTool, WorkspaceStatusWorkspace,
    };
    use serde_json::Value;

    fn sample_status_response() -> WorkspaceStatusResponse {
        WorkspaceStatusResponse {
            workspace: WorkspaceStatusWorkspace {
                id: Value::String("ws_1".to_string()),
                name: "Demo".to_string(),
                slug: "org/demo".to_string(),
                description: Some("workspace".to_string()),
                provisioned: true,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                updated_at: "2026-04-15T00:00:00Z".to_string(),
            },
            period: WorkspaceStatusPeriod {
                key: "7d".to_string(),
                started_at: "2026-04-08T00:00:00Z".to_string(),
                ended_at: "2026-04-15T00:00:00Z".to_string(),
            },
            generated_at: "2026-04-15T00:00:00Z".to_string(),
            inventory: WorkspaceStatusInventory {
                tagged_entries_count: 4,
                tagged_storage_bytes: 1024,
                tagged_hits: 10,
                version_count: 2,
                orphaned_entries_count: 0,
                orphaned_storage_bytes: 0,
                dedup_unique_bytes: 800,
                dedup_logical_bytes: 1200,
                dedup_savings_bytes: 400,
                dedup_ratio: 0.33,
            },
            operations: WorkspaceStatusOperations {
                cache: WorkspaceStatusCacheSummary {
                    total_requests: 12,
                    total_hits: 9,
                    lookup_requests: 12,
                    hit_rate: 0.75,
                    bytes_total: 4096,
                    avg_latency_ms: 12.5,
                    degraded_count: 0,
                },
                runtime: WorkspaceStatusRuntimeSummary {
                    total_queries: 12,
                    error_count: 0,
                    error_rate: 0.0,
                    avg_latency_ms: 10.0,
                    degraded_count: 0,
                },
                cache_health: WorkspaceStatusCacheHealth {
                    warm_hit_rate: 0.9,
                    cold_misses: 1,
                    recurring_misses: 2,
                    cold_pct: 0.33,
                    recurring_pct: 0.67,
                    session_miss_total: 3,
                    normal_misses: 3,
                    degraded_misses: 0,
                    total_misses: 3,
                    degraded_pct: 0.0,
                    excluded_seed_misses: 0,
                    excluded_seed_sessions: 0,
                },
                session_health: WorkspaceStatusSessionHealth {
                    total_sessions: 1,
                    healthy_sessions: 1,
                    error_sessions: 0,
                    degraded_sessions: 0,
                    avg_hit_rate: 0.75,
                    avg_duration_ms: 4000.0,
                },
            },
            savings: WorkspaceStatusSavings {
                cache_hits: 9,
                bytes_served: 2048,
                bytes_written: 1024,
                cli_restores: 2,
                cli_restore_bytes: 2048,
                cli_compression_saved: 512,
                cli_avg_restore_ms: 120.0,
                dedup_unique_bytes: 800,
                dedup_logical_bytes: 1200,
                dedup_savings_bytes: 400,
                dedup_ratio: 0.33,
            },
            tools: vec![WorkspaceStatusTool {
                tool: "turbo".to_string(),
                total: 12,
                hits: 9,
                misses: 3,
                lookup_total: 12,
                hit_rate: 0.75,
                warm_hit_rate: 0.9,
                recurring_misses: 2,
                new_key_misses: 1,
                bytes_total: 2048,
                avg_latency_ms: 12.5,
                degraded: 0,
            }],
            sessions: vec![WorkspaceStatusSession {
                session_id: "sess_1".to_string(),
                tool: "turbo".to_string(),
                project_hint: Some("demo".to_string()),
                phase_hint: Some("build".to_string()),
                metadata_hints: std::collections::BTreeMap::from([(
                    "lane".to_string(),
                    "ci".to_string(),
                )]),
                hit_rate: 0.75,
                hit_count: 9,
                miss_count: 3,
                error_count: 0,
                error_details: vec![WorkspaceStatusSessionError {
                    operation: "get".to_string(),
                    count: 0,
                }],
                duration_seconds: Some(4.0),
                bytes_read: 1024,
                bytes_written: 512,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                missed_keys: vec![WorkspaceStatusSessionMissedKey {
                    key_hash: "abc123".to_string(),
                    miss_count: 3,
                    sampled_key_prefix: Some("deps-".to_string()),
                }],
                review: None,
            }],
            missed_keys: vec![WorkspaceStatusMissedKey {
                key_hash: "abc123".to_string(),
                tool: "turbo".to_string(),
                miss_count: 3,
                last_seen_at: Some("2026-04-15T00:00:00Z".to_string()),
                sampled_key_prefix: Some("deps-".to_string()),
                miss_state: "recurring".to_string(),
            }],
        }
    }

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

    #[test]
    fn status_json_contract_adds_schema_version() {
        let value = crate::json_output::to_value(&sample_status_response()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["workspace"]["slug"], "org/demo");
        assert_eq!(value["tools"][0]["tool"], "turbo");
    }

    #[test]
    fn session_review_lines_render_customer_action_and_next_step() {
        let mut status = sample_status_response();
        status.sessions[0].review = Some(WorkspaceStatusSessionReview {
            primary_bottleneck: Some("cache_miss_bound".to_string()),
            state: "action_required".to_string(),
            summary: "No cache entry was found for this tag.".to_string(),
            service_side_issue: false,
            issue_candidates: vec![WorkspaceStatusSessionIssueCandidate {
                owner: "customer".to_string(),
                kind: "cache_miss_tag_not_found".to_string(),
                surface: "tui".to_string(),
                severity: "actionable".to_string(),
                confidence: Some(0.7),
                summary: "No cache entry was found for this tag.".to_string(),
                suggested_action: Some("Check tag/ref naming and trusted save path.".to_string()),
                evidence_refs: vec!["cache_session:sess_1:summary:lifecycle".to_string()],
            }],
        });

        let lines = session_review_lines(&status.sessions[0]);

        assert_eq!(
            lines,
            vec![
                "review: action - No cache entry was found for this tag.".to_string(),
                "next: Check tag/ref naming and trusted save path.".to_string()
            ]
        );
    }

    #[test]
    fn session_review_lines_stays_quiet_for_clear_reviews() {
        let mut status = sample_status_response();
        status.sessions[0].review = Some(WorkspaceStatusSessionReview {
            primary_bottleneck: None,
            state: "clear".to_string(),
            summary: "No customer action needed from the available cache telemetry.".to_string(),
            service_side_issue: false,
            issue_candidates: Vec::new(),
        });

        assert!(session_review_lines(&status.sessions[0]).is_empty());
    }
}

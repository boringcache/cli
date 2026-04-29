use crate::api::{
    ApiClient,
    models::workspace::{
        WorkspaceStatusResponse, WorkspaceStatusSession, WorkspaceStatusSessionIssueCandidate,
        WorkspaceStatusSessionReview,
    },
};
use anyhow::Result;

pub async fn execute(
    workspace_option: Option<String>,
    period: String,
    limit: u32,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_restore()?;
    let workspace = crate::command_support::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache analyze <workspace>",
    )
    .await?;
    let status = api_client
        .workspace_status(&workspace, &period, limit)
        .await?;

    if json_output {
        crate::json_output::print(&status)?;
        return Ok(());
    }

    render_analyze_report(&status);
    Ok(())
}

fn render_analyze_report(status: &WorkspaceStatusResponse) {
    crate::ui::blank_line();
    println!("Analyze");
    crate::commands::status::print_field("Workspace", &status.workspace.slug);
    crate::commands::status::print_field("Period", &format!("last {}", status.period.key));
    crate::commands::status::print_field(
        "Generated",
        &crate::commands::status::format_relative_time(&status.generated_at),
    );
    crate::ui::blank_line();

    for line in analyze_lines(status) {
        println!("  {line}");
    }
}

pub(crate) fn analyze_lines(status: &WorkspaceStatusResponse) -> Vec<String> {
    let mut lines = Vec::new();
    let mut customer_action_count = 0usize;
    let mut service_side_count = 0usize;

    for session in &status.sessions {
        let Some(review) = session.review.as_ref() else {
            continue;
        };
        if review.state == "clear"
            && review.issue_candidates.is_empty()
            && !review.service_side_issue
        {
            continue;
        }

        if review.service_side_issue {
            service_side_count += 1;
        }

        let mut rendered_customer_candidate = false;
        for candidate in review
            .issue_candidates
            .iter()
            .filter(|candidate| candidate.owner == "customer")
        {
            push_customer_candidate(&mut lines, session, review, candidate);
            customer_action_count += 1;
            rendered_customer_candidate = true;
        }

        if !rendered_customer_candidate && review.state == "action_required" {
            push_review_summary(&mut lines, "action", session, review);
            customer_action_count += 1;
        }
    }

    if customer_action_count == 0 {
        if service_side_count > 0 {
            lines.push(
                "service: BoringCache-side issue detected; keep the session id with the run."
                    .to_string(),
            );
        } else {
            lines.push(
                "clear: No customer action needed from the available cache telemetry.".to_string(),
            );
        }
    }

    lines
}

fn push_customer_candidate(
    lines: &mut Vec<String>,
    session: &WorkspaceStatusSession,
    review: &WorkspaceStatusSessionReview,
    candidate: &WorkspaceStatusSessionIssueCandidate,
) {
    let bottleneck = review
        .primary_bottleneck
        .as_deref()
        .unwrap_or(candidate.kind.as_str());
    lines.push(format!(
        "action: {}",
        crate::commands::status::truncate(&candidate.summary, 92)
    ));
    lines.push(format!(
        "session: {}  tool={}  bottleneck={}  {}",
        crate::commands::status::truncate(&session.session_id, 18),
        session.tool,
        bottleneck,
        crate::commands::status::format_relative_time(&session.created_at)
    ));
    if let Some(action) = candidate.suggested_action.as_deref() {
        lines.push(format!(
            "next: {}",
            crate::commands::status::truncate(action, 92)
        ));
    }
}

fn push_review_summary(
    lines: &mut Vec<String>,
    label: &str,
    session: &WorkspaceStatusSession,
    review: &WorkspaceStatusSessionReview,
) {
    lines.push(format!(
        "{label}: {}",
        crate::commands::status::truncate(&review.summary, 92)
    ));
    lines.push(format!(
        "session: {}  tool={}  {}",
        crate::commands::status::truncate(&session.session_id, 18),
        session.tool,
        crate::commands::status::format_relative_time(&session.created_at)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::workspace::{
        WorkspaceStatusCacheHealth, WorkspaceStatusCacheSummary, WorkspaceStatusInventory,
        WorkspaceStatusMissedKey, WorkspaceStatusOperations, WorkspaceStatusPeriod,
        WorkspaceStatusRuntimeSummary, WorkspaceStatusSavings, WorkspaceStatusSessionError,
        WorkspaceStatusSessionHealth, WorkspaceStatusSessionMissedKey, WorkspaceStatusTool,
        WorkspaceStatusWorkspace,
    };
    use serde_json::Value;
    use std::collections::BTreeMap;

    #[test]
    fn analyze_lines_render_customer_candidate() {
        let mut status = sample_status_response();
        status.sessions[0].review = Some(WorkspaceStatusSessionReview {
            primary_bottleneck: Some("cache_miss_bound".to_string()),
            state: "action_required".to_string(),
            summary: "A repeated cache miss needs a tag check.".to_string(),
            service_side_issue: false,
            issue_candidates: vec![WorkspaceStatusSessionIssueCandidate {
                owner: "customer".to_string(),
                kind: "cache_miss_tag_not_found".to_string(),
                surface: "tui".to_string(),
                severity: "actionable".to_string(),
                confidence: Some(0.8),
                summary: "No cache entry was found for this tag.".to_string(),
                suggested_action: Some("Check tag/ref naming and trusted save path.".to_string()),
                evidence_refs: vec!["cache_session:sess_1:summary:lifecycle".to_string()],
            }],
        });

        let lines = analyze_lines(&status);

        assert!(lines[0].starts_with("action: No cache entry"));
        assert!(lines[1].contains("bottleneck=cache_miss_bound"));
        assert_eq!(
            lines[2],
            "next: Check tag/ref naming and trusted save path.".to_string()
        );
    }

    #[test]
    fn analyze_lines_stays_customer_clear_for_old_or_clear_reviews() {
        let status = sample_status_response();

        assert_eq!(
            analyze_lines(&status),
            vec![
                "clear: No customer action needed from the available cache telemetry.".to_string()
            ]
        );
    }

    #[test]
    fn analyze_lines_hides_service_details_without_customer_candidates() {
        let mut status = sample_status_response();
        status.sessions[0].review = Some(WorkspaceStatusSessionReview {
            primary_bottleneck: Some("backend_api_bound".to_string()),
            state: "service_side_issue".to_string(),
            summary: "Backend API latency is elevated.".to_string(),
            service_side_issue: true,
            issue_candidates: Vec::new(),
        });

        assert_eq!(
            analyze_lines(&status),
            vec![
                "service: BoringCache-side issue detected; keep the session id with the run."
                    .to_string()
            ]
        );
    }

    fn sample_status_response() -> WorkspaceStatusResponse {
        WorkspaceStatusResponse {
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
            inventory: WorkspaceStatusInventory {
                tagged_entries_count: 1,
                tagged_storage_bytes: 1024,
                tagged_hits: 1,
                version_count: 1,
                orphaned_entries_count: 0,
                orphaned_storage_bytes: 0,
                dedup_unique_bytes: 1024,
                dedup_logical_bytes: 1024,
                dedup_savings_bytes: 0,
                dedup_ratio: 0.0,
            },
            operations: WorkspaceStatusOperations {
                cache: WorkspaceStatusCacheSummary {
                    total_requests: 3,
                    total_hits: 2,
                    lookup_requests: 3,
                    hit_rate: 0.67,
                    bytes_total: 512,
                    avg_latency_ms: 12.0,
                    degraded_count: 0,
                },
                runtime: WorkspaceStatusRuntimeSummary {
                    total_queries: 0,
                    error_count: 0,
                    error_rate: 0.0,
                    avg_latency_ms: 0.0,
                    degraded_count: 0,
                },
                cache_health: WorkspaceStatusCacheHealth {
                    warm_hit_rate: 0.67,
                    cold_misses: 1,
                    recurring_misses: 0,
                    cold_pct: 1.0,
                    recurring_pct: 0.0,
                    session_miss_total: 1,
                    normal_misses: 1,
                    degraded_misses: 0,
                    total_misses: 1,
                    degraded_pct: 0.0,
                    excluded_seed_misses: 0,
                    excluded_seed_sessions: 0,
                },
                session_health: WorkspaceStatusSessionHealth {
                    total_sessions: 1,
                    healthy_sessions: 1,
                    error_sessions: 0,
                    degraded_sessions: 0,
                    avg_duration_ms: 2000.0,
                    avg_hit_rate: 0.67,
                },
            },
            savings: WorkspaceStatusSavings {
                cache_hits: 2,
                bytes_served: 512,
                bytes_written: 1024,
                cli_restores: 0,
                cli_restore_bytes: 0,
                cli_compression_saved: 0,
                cli_avg_restore_ms: 0.0,
                dedup_unique_bytes: 1024,
                dedup_logical_bytes: 1024,
                dedup_savings_bytes: 0,
                dedup_ratio: 0.0,
            },
            tools: vec![WorkspaceStatusTool {
                tool: "gradle".to_string(),
                total: 3,
                hits: 2,
                misses: 1,
                lookup_total: 3,
                hit_rate: 0.67,
                warm_hit_rate: 0.67,
                recurring_misses: 0,
                new_key_misses: 1,
                bytes_total: 512,
                avg_latency_ms: 12.0,
                degraded: 0,
            }],
            sessions: vec![WorkspaceStatusSession {
                session_id: "session-123456789".to_string(),
                tool: "gradle".to_string(),
                project_hint: None,
                phase_hint: None,
                metadata_hints: BTreeMap::new(),
                hit_rate: 0.67,
                hit_count: 2,
                miss_count: 1,
                error_count: 0,
                error_details: Vec::<WorkspaceStatusSessionError>::new(),
                duration_seconds: Some(2.0),
                bytes_read: 512,
                bytes_written: 1024,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                missed_keys: Vec::<WorkspaceStatusSessionMissedKey>::new(),
                review: None,
            }],
            missed_keys: Vec::<WorkspaceStatusMissedKey>::new(),
        }
    }
}

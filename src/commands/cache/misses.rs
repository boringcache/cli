use crate::api::{ApiClient, models::workspace::WorkspaceMissesResponse};
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
        "boringcache misses <workspace>",
    )
    .await?;
    let offset = (page.saturating_sub(1)).saturating_mul(limit);
    let response = api_client
        .workspace_misses(&workspace, &period, limit, offset)
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_misses_report(&response);
    Ok(())
}

fn render_misses_report(response: &WorkspaceMissesResponse) {
    crate::ui::blank_line();
    println!("Misses");
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    crate::commands::status::print_field("Period", &format!("last {}", response.period.key));
    crate::commands::status::print_field("Showing", &showing_range(&response.pagination));
    crate::commands::status::print_field(
        "Recurring",
        &format!(
            "{} ({})",
            response.cache_health.recurring_misses,
            crate::commands::status::format_percent(response.cache_health.recurring_pct)
        ),
    );
    crate::commands::status::print_field(
        "Cold",
        &format!(
            "{} ({})",
            response.cache_health.cold_misses,
            crate::commands::status::format_percent(response.cache_health.cold_pct)
        ),
    );
    crate::ui::blank_line();

    if response.missed_keys.is_empty() {
        println!("  none");
        return;
    }

    for missed_key in &response.missed_keys {
        let prefix = missed_key
            .sampled_key_prefix
            .as_deref()
            .map(|value| crate::commands::status::truncate(value, 44))
            .unwrap_or_else(|| missed_key.key_hash.chars().take(12).collect());
        let seen = missed_key
            .last_seen_at
            .as_deref()
            .map(crate::commands::status::format_relative_time)
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

    if response.pagination.has_more {
        crate::ui::blank_line();
        println!(
            "Next page: boringcache misses {} --page {} --limit {}",
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

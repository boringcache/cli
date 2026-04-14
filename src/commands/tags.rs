use crate::api::{ApiClient, models::workspace::WorkspaceTagsResponse};
use crate::progress::format_bytes;
use anyhow::Result;

pub async fn execute(
    workspace_option: Option<String>,
    filter: Option<String>,
    include_system: bool,
    limit: u32,
    page: u32,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_restore()?;
    let workspace = crate::command_support::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache tags <workspace>",
    )
    .await?;
    let offset = (page.saturating_sub(1)).saturating_mul(limit);
    let response = api_client
        .workspace_tags(&workspace, filter.as_deref(), include_system, limit, offset)
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_tags_report(&response);
    Ok(())
}

fn render_tags_report(response: &WorkspaceTagsResponse) {
    crate::ui::blank_line();
    println!("Tags");
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    if let Some(filter) = response.filter.query.as_deref() {
        crate::commands::status::print_field("Filter", filter);
    }
    crate::commands::status::print_field(
        "Scope",
        if response.filter.include_system {
            "all tags"
        } else {
            "human tags"
        },
    );
    crate::commands::status::print_field("Showing", &showing_range(&response.pagination));
    crate::ui::blank_line();

    if response.tags.is_empty() {
        println!("  none");
        return;
    }

    println!(
        "  {:<8} {:<32} {:<22} {:>6} {:>10} {:<12}",
        "TYPE", "TAG", "PRIMARY", "HITS", "SIZE", "UPLOADED"
    );
    println!("  {}", "-".repeat(99));

    for tag in &response.tags {
        println!(
            "  {:<8} {:<32} {:<22} {:>6} {:>10} {:<12}",
            tag_kind(tag),
            crate::commands::status::truncate(&tag.name, 32),
            crate::commands::status::truncate(&tag.primary_tag, 22),
            tag.hit_count,
            format_bytes(tag.stored_size_bytes),
            format_optional_relative_time(tag.uploaded_at.as_deref())
        );
    }

    crate::ui::blank_line();
    println!("Inspect: boringcache inspect <tag>");

    if response.pagination.has_more {
        println!("Next page: {}", next_page_command(response));
    }
}

fn tag_kind(tag: &crate::api::models::workspace::WorkspaceTagFeedItem) -> &'static str {
    if tag.system {
        "system"
    } else if tag.primary {
        "primary"
    } else {
        "alias"
    }
}

fn format_optional_relative_time(timestamp: Option<&str>) -> String {
    timestamp
        .map(crate::commands::status::format_relative_time)
        .unwrap_or_else(|| "-".to_string())
}

fn next_page_command(response: &WorkspaceTagsResponse) -> String {
    let mut parts = vec![
        "boringcache".to_string(),
        "tags".to_string(),
        response.workspace.slug.clone(),
        format!(
            "--page {}",
            response.pagination.offset / response.pagination.limit + 2
        ),
        format!("--limit {}", response.pagination.limit),
    ];

    if let Some(filter) = response.filter.query.as_deref() {
        parts.push(format!("--filter {}", shell_quote(filter)));
    }
    if response.filter.include_system {
        parts.push("--all".to_string());
    }

    parts.join(" ")
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
    {
        value.to_string()
    } else {
        format!("{value:?}")
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
    use super::*;
    use crate::api::models::workspace::{
        WorkspacePagination, WorkspaceSummaryContext, WorkspaceTagFeedItem, WorkspaceTagsFilter,
        WorkspaceTagsResponse,
    };

    #[test]
    fn next_page_command_preserves_filter_and_all_flag() {
        let response = WorkspaceTagsResponse {
            workspace: WorkspaceSummaryContext {
                name: "testing".to_string(),
                slug: "org/testing".to_string(),
            },
            filter: WorkspaceTagsFilter {
                query: Some("ruby current".to_string()),
                include_system: true,
            },
            pagination: WorkspacePagination {
                limit: 20,
                offset: 20,
                total: 45,
                returned: 20,
                has_more: true,
            },
            tags: vec![WorkspaceTagFeedItem {
                name: "ruby-current".to_string(),
                primary: true,
                system: false,
                primary_tag: "ruby-current".to_string(),
                cache_entry_id: "entry-1".to_string(),
                manifest_root_digest: "sha256:abc".to_string(),
                storage_mode: "archive".to_string(),
                stored_size_bytes: 1024,
                hit_count: 3,
                uploaded_at: None,
                last_accessed_at: None,
            }],
        };

        assert_eq!(
            next_page_command(&response),
            r#"boringcache tags org/testing --page 3 --limit 20 --filter "ruby current" --all"#
        );
    }

    #[test]
    fn showing_range_handles_empty_page() {
        let pagination = WorkspacePagination {
            limit: 20,
            offset: 20,
            total: 20,
            returned: 0,
            has_more: false,
        };

        assert_eq!(showing_range(&pagination), "0 of 20");
    }
}

use super::*;
use crate::api::models::workspace::{
    WorkspacePagination, WorkspaceSummaryContext, WorkspaceTagsFilter,
};

fn sample_tags_response(total: u32, returned: u32) -> WorkspaceTagsResponse {
    WorkspaceTagsResponse {
        workspace: WorkspaceSummaryContext {
            name: "testing".to_string(),
            slug: "org/testing".to_string(),
        },
        filter: WorkspaceTagsFilter {
            query: None,
            include_system: false,
        },
        pagination: WorkspacePagination {
            limit: 25,
            offset: 25,
            total,
            returned,
            has_more: false,
        },
        tags: vec![],
    }
}

fn sample_tag(
    name: &str,
    primary: bool,
    system: bool,
    uploaded_at: Option<&str>,
    last_accessed_at: Option<&str>,
) -> WorkspaceTagFeedItem {
    WorkspaceTagFeedItem {
        name: name.to_string(),
        primary,
        system,
        primary_tag: name.to_string(),
        cache_entry_id: format!("entry-{name}"),
        manifest_root_digest: format!("sha256:{name}"),
        storage_mode: "archive".to_string(),
        stored_size_bytes: 100,
        hit_count: 1,
        uploaded_at: uploaded_at.map(str::to_string),
        last_accessed_at: last_accessed_at.map(str::to_string),
    }
}

#[test]
fn tag_page_count_handles_empty_state() {
    assert_eq!(tag_page_count(&sample_tags_response(0, 0)), 1);
    assert_eq!(tag_page_count(&sample_tags_response(76, 25)), 4);
}

#[test]
fn dashboard_tags_page_keeps_primary_human_tags_sorted_by_recent_activity() {
    let mut response = sample_tags_response(5, 5);
    response.pagination.offset = 0;
    response.tags = vec![
        sample_tag(
            "old-primary",
            true,
            false,
            Some("2026-04-27T07:00:00Z"),
            Some("2026-04-27T08:00:00Z"),
        ),
        sample_tag(
            "fresh-alias",
            false,
            false,
            Some("2026-04-27T07:00:00Z"),
            Some("2026-04-27T12:00:00Z"),
        ),
        sample_tag(
            "fresh-system",
            true,
            true,
            Some("2026-04-27T07:00:00Z"),
            Some("2026-04-27T11:00:00Z"),
        ),
        sample_tag(
            "uploaded-only",
            true,
            false,
            Some("2026-04-27T09:00:00Z"),
            None,
        ),
        sample_tag(
            "fresh-primary",
            true,
            false,
            Some("2026-04-27T07:00:00Z"),
            Some("2026-04-27T10:00:00Z"),
        ),
    ];

    let page = dashboard_tags_page(response, 2, 1);

    assert_eq!(page.pagination.total, 3);
    assert_eq!(page.pagination.returned, 2);
    assert!(page.pagination.has_more);
    assert_eq!(
        page.tags
            .iter()
            .map(|tag| tag.name.as_str())
            .collect::<Vec<_>>(),
        vec!["fresh-primary", "uploaded-only"]
    );
}

#[test]
fn dashboard_tags_page_paginates_after_filtering() {
    let mut response = sample_tags_response(4, 4);
    response.pagination.offset = 0;
    response.tags = vec![
        sample_tag("first", true, false, Some("2026-04-27T10:00:00Z"), None),
        sample_tag(
            "ignored-alias",
            false,
            false,
            Some("2026-04-27T09:00:00Z"),
            None,
        ),
        sample_tag("second", true, false, Some("2026-04-27T08:00:00Z"), None),
        sample_tag("third", true, false, Some("2026-04-27T07:00:00Z"), None),
    ];

    let page = dashboard_tags_page(response, 2, 2);

    assert_eq!(page.pagination.total, 3);
    assert_eq!(page.pagination.offset, 2);
    assert_eq!(page.pagination.returned, 1);
    assert!(!page.pagination.has_more);
    assert_eq!(page.tags[0].name, "third");
}

#[test]
fn resolve_selected_tag_index_falls_back_to_zero() {
    let response = WorkspaceTagsResponse {
        workspace: WorkspaceSummaryContext {
            name: "testing".to_string(),
            slug: "org/testing".to_string(),
        },
        filter: WorkspaceTagsFilter {
            query: None,
            include_system: false,
        },
        pagination: WorkspacePagination {
            limit: 25,
            offset: 0,
            total: 2,
            returned: 2,
            has_more: false,
        },
        tags: vec![
            WorkspaceTagFeedItem {
                name: "alpha".to_string(),
                primary: true,
                system: false,
                primary_tag: "alpha".to_string(),
                cache_entry_id: "entry-a".to_string(),
                manifest_root_digest: "sha256:a".to_string(),
                storage_mode: "archive".to_string(),
                stored_size_bytes: 100,
                hit_count: 1,
                uploaded_at: None,
                last_accessed_at: None,
            },
            WorkspaceTagFeedItem {
                name: "beta".to_string(),
                primary: false,
                system: false,
                primary_tag: "alpha".to_string(),
                cache_entry_id: "entry-b".to_string(),
                manifest_root_digest: "sha256:b".to_string(),
                storage_mode: "archive".to_string(),
                stored_size_bytes: 200,
                hit_count: 2,
                uploaded_at: None,
                last_accessed_at: None,
            },
        ],
    };

    assert_eq!(
        resolve_selected_tag_index(&response, Some("beta".to_string())),
        1
    );
    assert_eq!(
        resolve_selected_tag_index(&response, Some("missing".to_string())),
        0
    );
}

#[test]
fn dashboard_layout_mode_supports_standard_terminals() {
    assert_eq!(
        dashboard_layout_mode(Rect::new(0, 0, 79, 24)),
        LayoutMode::TooSmall
    );
    assert_eq!(
        dashboard_layout_mode(Rect::new(0, 0, 80, 24)),
        LayoutMode::Compact
    );
    assert_eq!(
        dashboard_layout_mode(Rect::new(0, 0, 100, 28)),
        LayoutMode::Full
    );
}

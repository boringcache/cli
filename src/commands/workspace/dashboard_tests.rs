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

#[test]
fn tag_page_count_handles_empty_state() {
    assert_eq!(tag_page_count(&sample_tags_response(0, 0)), 1);
    assert_eq!(tag_page_count(&sample_tags_response(76, 25)), 4);
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

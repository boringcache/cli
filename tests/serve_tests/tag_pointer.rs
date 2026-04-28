use super::*;

#[tokio::test]
async fn test_tag_pointer_returns_cache_entry_id() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("etag", "\"42\"")
        .with_body(
            serde_json::to_string(&json!({
                "tag": "registry",
                "cache_entry_id": "entry-abc-123",
                "manifest_root_digest": "sha256:aaa",
                "version": "42"
            }))
            .unwrap(),
        )
        .create_async()
        .await;

    use boring_cache_cli::api::client::TagPointerPollResult;
    let result = _state
        .api_client
        .tag_pointer(&_state.workspace, "registry", None)
        .await
        .expect("tag_pointer should succeed");

    match result {
        TagPointerPollResult::Changed { pointer, etag } => {
            assert_eq!(pointer.cache_entry_id.as_deref(), Some("entry-abc-123"));
            assert_eq!(pointer.manifest_root_digest.as_deref(), Some("sha256:aaa"));
            assert_eq!(etag.as_deref(), Some("\"42\""));
        }
        other => panic!("Expected Changed, got {:?}", other),
    }

    pointer_mock.assert_async().await;
}

#[tokio::test]
async fn test_tag_pointer_returns_not_modified_on_304() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .match_header("If-None-Match", "\"42\"")
        .with_status(304)
        .create_async()
        .await;

    use boring_cache_cli::api::client::TagPointerPollResult;
    let result = _state
        .api_client
        .tag_pointer(&_state.workspace, "registry", Some("\"42\""))
        .await
        .expect("tag_pointer should succeed");

    assert!(matches!(result, TagPointerPollResult::NotModified));
    pointer_mock.assert_async().await;
}

#[tokio::test]
async fn test_tag_pointer_returns_not_found_on_404() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .with_status(404)
        .with_body("{\"error\": \"not found\"}")
        .create_async()
        .await;

    use boring_cache_cli::api::client::TagPointerPollResult;
    let result = _state
        .api_client
        .tag_pointer(&_state.workspace, "registry", None)
        .await
        .expect("tag_pointer should succeed");

    assert!(matches!(result, TagPointerPollResult::NotFound));
    pointer_mock.assert_async().await;
}

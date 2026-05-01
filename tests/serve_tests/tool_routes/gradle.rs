use super::*;

#[tokio::test]
async fn test_gradle_put_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let cache_key = "1234abcd";
    let payload = b"gradle-cache-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_file_pointer(&payload_digest, payload.len() as u64);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let _save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": "unused",
                "cache_entry_id": "entry-gradle-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "upload_session_id": "session-entry-gradle-kv",
                "manifest_upload_url": format!("{}/manifest-upload-gradle", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-upload-gradle", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-gradle")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-gradle")
        .match_body(Matcher::Any)
        .with_status(200)
        .create_async()
        .await;

    let _pointer_mock = server
        .mock(
            "GET",
            "/v2/workspaces/org/repo/caches/tags/registry/pointer",
        )
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "13",
                "cache_entry_id": "entry-gradle-kv",
                "status": "ready"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _confirm_mock = server
        .mock(
            "PUT",
            "/v2/workspaces/org/repo/caches/tags/registry/publish",
        )
        .match_header("if-match", "13")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "13",
                "status": "confirmed",
                "cache_entry_id": "entry-gradle-kv"
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/cache/{cache_key}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let _restore_get_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-gradle-kv",
                "manifest_url": format!("{}/pointer-download-gradle", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-gradle")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-gradle", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-gradle")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cache/{cache_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_gradle_get_uses_default_restore_root_after_transient_branch_error() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.registry_root_tag = "head-registry".to_string();
    state.registry_restore_root_tags =
        vec!["head-registry".to_string(), "default-registry".to_string()];

    let cache_key = "fallback-gradle-key";
    let payload = b"gradle-fallback-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_entries = vec![(
        format!("gradle/{cache_key}"),
        payload_digest.clone(),
        payload.len() as u64,
    )];
    let pointer_bytes = make_kv_pointer(&pointer_entries);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let head_restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=head-registry$".to_string()),
        )
        .expect(3)
        .with_status(500)
        .with_body("temporary backend failure")
        .create_async()
        .await;

    let default_restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(
                r"^/v2/workspaces/org/repo/caches\?entries=default-registry$".to_string(),
            ),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "default-registry",
                "status": "hit",
                "cache_entry_id": "entry-gradle-fallback",
                "manifest_url": format!("{}/pointer-download-gradle-fallback", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_get_mock = server
        .mock("GET", "/pointer-download-gradle-fallback")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(1)
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": payload_digest,
                    "url": format!("{}/blob-download-gradle-fallback", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let blob_download_mock = server
        .mock("GET", "/blob-download-gradle-fallback")
        .expect(1)
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cache/{cache_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), payload);
    head_restore_mock.assert_async().await;
    default_restore_mock.assert_async().await;
    pointer_get_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_download_mock.assert_async().await;
}

#[tokio::test]
async fn test_gradle_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/cache/test-key")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_gradle_get_miss_returns_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri("/cache/missing-gradle-key")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_gradle_skip_rule_returns_synthetic_miss() {
    let server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.proxy_skip_rules = Arc::new(vec![ProxySkipRule {
        tool: "gradle".to_string(),
        action: ":app:processReleaseResources".to_string(),
        reason: Some("net loss".to_string()),
    }]);

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::GET)
            .uri("/cache/expensive-action-output")
            .header("X-Boringcache-Action", ":app:processReleaseResources")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get("x-boringcache-skip-rule").unwrap(),
        "boringcache_skip_rule"
    );
    assert_eq!(state.skip_rule_metrics.matched_count(), 1);
    let summary = boring_cache_cli::serve::state::build_cache_session_summary(&state);
    assert_eq!(
        summary.lifecycle["miss_reason_counts"]["boringcache_skip_rule"],
        1
    );
    assert_eq!(
        summary.lifecycle["product_behavior_reason_counts"]["boringcache_skip_rule"],
        1
    );
}

#[tokio::test]
async fn test_gradle_put_returns_413_when_spool_budget_exceeded() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_MAX_SPOOL_BYTES", "1");
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/cache/oversized-entry")
            .body(Body::from("too-large"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

use super::*;

#[tokio::test]
async fn test_turborepo_status_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let unauth = tower::ServiceExt::oneshot(
        app.clone(),
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let auth = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/status")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(auth.status(), StatusCode::OK);
    let body = auth.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["status"], "enabled");
}

#[tokio::test]
async fn test_turborepo_status_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts/status")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_turborepo_status_rejects_invalid_bearer_header() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/status")
            .header("authorization", "token only")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_turborepo_query_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": ["a1b2"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_turborepo_query_rejects_invalid_payload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from("not-json"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_json_error(&parsed, "bad_request");
}

#[tokio::test]
async fn test_turborepo_put_head_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "aabbcc1234";
    let payload = b"turbo-cache-payload";
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
                "cache_entry_id": "entry-turbo-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "upload_session_id": "session-entry-turbo-kv",
                "manifest_upload_url": format!("{}/manifest-upload-turbo", server.url()),
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
                    "url": format!("{}/blob-upload-turbo", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-turbo")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-turbo")
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
                "version": "15",
                "cache_entry_id": "entry-turbo-kv",
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
        .match_header("if-match", "15")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "15",
                "status": "confirmed",
                "cache_entry_id": "entry-turbo-kv"
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
            .uri(format!("/v8/artifacts/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", payload.len().to_string())
            .header("x-artifact-duration", "123")
            .header("x-artifact-tag", STANDARD.encode("signed-tag"))
            .header("x-artifact-sha", "abc123def456")
            .header("x-artifact-dirty-hash", "dirty789")
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::ACCEPTED);
    let put_body = put_response.into_body().collect().await.unwrap().to_bytes();
    let put_json: serde_json::Value = serde_json::from_slice(&put_body).unwrap();
    assert_eq!(put_json["urls"], json!([]));

    let _restore_head_mock = server
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
                "cache_entry_id": "entry-turbo-kv",
                "manifest_url": format!("{}/pointer-download-turbo", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_head_mock = server
        .mock("GET", "/pointer-download-turbo")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v8/artifacts/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    assert_eq!(
        head_response.headers().get("x-artifact-duration").unwrap(),
        "123"
    );
    assert_eq!(
        head_response.headers().get("x-artifact-sha").unwrap(),
        "abc123def456"
    );
    assert_eq!(
        head_response
            .headers()
            .get("x-artifact-dirty-hash")
            .unwrap(),
        "dirty789"
    );
    assert!(head_response.headers().get("x-artifact-tag").is_none());

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
                "cache_entry_id": "entry-turbo-kv",
                "manifest_url": format!("{}/pointer-download-turbo-get", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-turbo-get")
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
                    "url": format!("{}/blob-download-turbo", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-turbo")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v8/artifacts/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    assert_eq!(
        get_response.headers().get("x-artifact-duration").unwrap(),
        "123"
    );
    assert_eq!(
        get_response
            .headers()
            .get("x-artifact-tag")
            .and_then(|value| value.to_str().ok()),
        Some(STANDARD.encode("signed-tag").as_str())
    );
    assert_eq!(
        get_response.headers().get("x-artifact-sha").unwrap(),
        "abc123def456"
    );
    assert_eq!(
        get_response.headers().get("x-artifact-dirty-hash").unwrap(),
        "dirty789"
    );
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_turborepo_artifact_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/v8/artifacts/aabbcc")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_turborepo_artifact_get_miss_returns_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/aabbcc")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_turborepo_query_artifacts_returns_metadata_map() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let payload_a = b"hello-world";
    let payload_b = b"second-artifact-data";

    let app = build_router(state.clone());
    let put_a = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/a1b2")
            .header("authorization", "Bearer token")
            .header("content-length", payload_a.len().to_string())
            .header("x-artifact-duration", "55")
            .header("x-artifact-tag", STANDARD.encode("tag-a1"))
            .body(Body::from(payload_a.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_a.status(), StatusCode::ACCEPTED);

    let app = build_router(state.clone());
    let put_b = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/c3d4")
            .header("authorization", "Bearer token")
            .header("content-length", payload_b.len().to_string())
            .header("x-artifact-duration", "99")
            .header("x-artifact-tag", STANDARD.encode("tag-c3"))
            .body(Body::from(payload_b.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_b.status(), StatusCode::ACCEPTED);

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": ["a1b2", "c3d4"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["a1b2"]["size"], payload_a.len() as u64);
    assert_eq!(parsed["c3d4"]["size"], payload_b.len() as u64);
    assert_eq!(parsed["a1b2"]["taskDurationMs"], 55);
    assert_eq!(parsed["c3d4"]["taskDurationMs"], 99);
    assert_eq!(parsed["a1b2"]["tag"], json!(STANDARD.encode("tag-a1")));
    assert_eq!(parsed["c3d4"]["tag"], json!(STANDARD.encode("tag-c3")));
}

#[tokio::test]
async fn test_turborepo_put_rejects_invalid_openapi_headers() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/aabbcc")
            .header("authorization", "Bearer token")
            .header("content-length", "7")
            .header("x-artifact-tag", "not base64")
            .body(Body::from("payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_json_error(&parsed, "bad_request");
}

#[tokio::test]
async fn test_turborepo_events_accepts_post_with_bearer() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts/events")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!([
                    {
                        "sessionId": "018f6f74-0a8a-7c50-9d5a-4db9957982d6",
                        "source": "REMOTE",
                        "event": "HIT",
                        "hash": "hash-a",
                        "duration": 12
                    }
                ])
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_turborepo_events_rejects_invalid_payload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v8/artifacts/events")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"not":"an-array"}"#))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_json_error(&parsed, "bad_request");
}

#[tokio::test]
async fn test_turborepo_events_rejects_get() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v8/artifacts/events")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_turborepo_invalid_put_path_returns_bad_request() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v8/artifacts/not-a-hex-hash")
            .header("authorization", "Bearer token")
            .header("content-length", "7")
            .body(Body::from("payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_json_error(&parsed, "bad_request");
}

use super::*;

#[tokio::test]
async fn test_bazel_cas_put_head_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let payload = b"bazel-cas-payload";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let bazel_key = payload_digest
        .strip_prefix("sha256:")
        .expect("sha256 prefix present");
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
                "cache_entry_id": "entry-bazel-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "upload_session_id": "session-entry-bazel-kv",
                "manifest_upload_url": format!("{}/manifest-upload", server.url()),
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
                    "url": format!("{}/blob-upload", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload")
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
                "version": "9",
                "cache_entry_id": "entry-bazel-kv",
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
        .match_header("if-match", "9")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "9",
                "status": "confirmed",
                "cache_entry_id": "entry-bazel-kv"
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
            .uri(format!("/cas/{bazel_key}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

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
                "cache_entry_id": "entry-bazel-kv",
                "manifest_url": format!("{}/pointer-download", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_head_mock = server
        .mock("GET", "/pointer-download")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/cas/{bazel_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let expected_content_length = payload.len().to_string();
    assert_eq!(
        head_response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_length.as_str())
    );
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

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
                "cache_entry_id": "entry-bazel-kv",
                "manifest_url": format!("{}/pointer-download-get", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-get")
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
                    "url": format!("{}/blob-download", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{bazel_key}"))
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
async fn test_bazel_route_rejects_invalid_digest() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/ac/not-a-sha256")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_bazel_put_rejects_digest_key_mismatch() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/cas/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .body(Body::from("mismatched-bazel-payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_bazel_ac_put_keeps_action_result_payload_opaque() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/ac/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .body(Body::from("action-result-metadata-is-not-cas-bytes"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_bazel_cas_get_ignores_pending_digest_mismatch() {
    let server = Server::new_async().await;
    let (state, home, _guard) = setup(&server).await;

    let key = cas_file::prefixed_sha256_digest(b"expected-bazel-cas-payload")
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let mismatched_payload = b"mismatched-pending-bazel-cas-payload";
    let mismatched_digest = cas_file::prefixed_sha256_digest(mismatched_payload);
    let temp_path = home.path().join("mismatched-pending-bazel-cas.bin");
    tokio::fs::write(&temp_path, mismatched_payload)
        .await
        .expect("write pending blob");
    {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            format!("bazel_cas/{key}"),
            BlobDescriptor {
                digest: mismatched_digest,
                size_bytes: mismatched_payload.len() as u64,
            },
            temp_path,
        );
    }
    {
        let mut published = state.kv_published_index.write().await;
        published.set_empty();
    }

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_bazel_cas_get_ignores_published_digest_mismatch() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = cas_file::prefixed_sha256_digest(b"expected-published-bazel-cas-payload")
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let mismatched_payload = b"mismatched-published-bazel-cas-payload";
    let mismatched_digest = cas_file::prefixed_sha256_digest(mismatched_payload);
    let blob_mock = server
        .mock("GET", "/mismatched-published-bazel-cas")
        .expect(0)
        .with_status(200)
        .with_body(mismatched_payload)
        .create_async()
        .await;

    {
        let mut published = state.kv_published_index.write().await;
        published.update(
            std::collections::HashMap::from([(
                format!("bazel_cas/{key}"),
                BlobDescriptor {
                    digest: mismatched_digest.clone(),
                    size_bytes: mismatched_payload.len() as u64,
                },
            )]),
            vec![BlobDescriptor {
                digest: mismatched_digest.clone(),
                size_bytes: mismatched_payload.len() as u64,
            }],
            "entry-bazel-mismatched-published".to_string(),
        );
        published.set_download_url(
            mismatched_digest,
            format!("{}/mismatched-published-bazel-cas", server.url()),
        );
    }

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_bazel_cas_get_ignores_backend_index_digest_mismatch() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = cas_file::prefixed_sha256_digest(b"expected-backend-bazel-cas-payload")
        .strip_prefix("sha256:")
        .expect("sha256 prefix")
        .to_string();
    let mismatched_payload = b"mismatched-backend-bazel-cas-payload";
    let mismatched_digest = cas_file::prefixed_sha256_digest(mismatched_payload);
    let pointer_bytes = make_kv_pointer(&[(
        format!("bazel_cas/{key}"),
        mismatched_digest.clone(),
        mismatched_payload.len() as u64,
    )]);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "registry",
                "status": "hit",
                "cache_entry_id": "entry-bazel-mismatched-backend",
                "manifest_url": format!("{}/pointer-bazel-mismatched-backend", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;
    let pointer_mock = server
        .mock("GET", "/pointer-bazel-mismatched-backend")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;
    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(0)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": mismatched_digest,
                    "url": format!("{}/mismatched-backend-bazel-cas", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/cas/{key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
}

#[tokio::test]
async fn test_bazel_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/ac/{digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_bazel_ac_and_cas_misses_return_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    for path in [format!("/ac/{digest}"), format!("/cas/{digest}")] {
        let response = tower::ServiceExt::oneshot(
            build_router(state.clone()),
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    restore_mock.assert_async().await;
}

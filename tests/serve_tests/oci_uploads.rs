use super::*;

#[tokio::test]
async fn test_upload_start_and_finalize() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = response
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.contains(&uuid));

    let app = build_router(state.clone());
    let status_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(status_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        status_response
            .headers()
            .get("Docker-Upload-UUID")
            .and_then(|value| value.to_str().ok()),
        Some(uuid.as_str())
    );
    assert_eq!(
        status_response
            .headers()
            .get("Range")
            .and_then(|value| value.to_str().ok()),
        Some("0-0")
    );

    let chunk_data = b"test blob data";
    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::from(chunk_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let range = response
        .headers()
        .get("Range")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(range, format!("0-{}", chunk_data.len() - 1));

    let digest = cas_oci::prefixed_sha256_digest(chunk_data);
    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );
}

#[tokio::test]
async fn test_upload_digest_mismatch_returns_error() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let chunk_data = b"some data";
    let app = build_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::from(chunk_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/my-cache/blobs/uploads/{uuid}?digest={wrong_digest}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
}

#[tokio::test]
async fn test_put_upload_body_stream_error_returns_internal_error() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let start = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = start
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let digest = cas_oci::prefixed_sha256_digest(b"stream-error");
    let stream = futures_util::stream::once(async {
        let err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        Err::<axum::body::Bytes, std::io::Error>(err)
    });

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .body(Body::from_stream(stream))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");
    assert!(
        parsed["errors"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("body stream error")
    );
}

#[tokio::test]
async fn test_patch_retry_with_stale_content_range_returns_416() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let blob_data = b"retry-safe-blob";
    let range = format!("0-{}", blob_data.len() - 1);
    let app = build_router(state.clone());
    let first_patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", range.clone())
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(first_patch.status(), StatusCode::ACCEPTED);

    let app = build_router(state.clone());
    let retry_patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", &range)
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(retry_patch.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(retry_patch.headers().get("Range").unwrap(), range.as_str());

    let digest = cas_oci::prefixed_sha256_digest(blob_data);
    let app = build_router(state.clone());
    let finalize = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_put_upload_uses_content_range_offset() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let prefix = b"hello ";
    let suffix = b"world";
    let app = build_router(state.clone());
    let patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", "0-5")
            .body(Body::from(prefix.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(patch.status(), StatusCode::ACCEPTED);

    let full_blob = b"hello world";
    let digest = cas_oci::prefixed_sha256_digest(full_blob);
    let app = build_router(state.clone());
    let finalize = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .header("Content-Range", "6-10")
            .body(Body::from(suffix.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_put_upload_with_stale_content_range_returns_416() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let stale_blob = b"this-is-an-older-and-longer-blob";
    let app = build_router(state.clone());
    let patch = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .header("Content-Range", format!("0-{}", stale_blob.len() - 1))
            .body(Body::from(stale_blob.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(patch.status(), StatusCode::ACCEPTED);

    let final_blob = b"final-v1";
    let digest = cas_oci::prefixed_sha256_digest(final_blob);
    let app = build_router(state.clone());
    let finalize = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}?digest={digest}"))
            .header("Content-Range", format!("0-{}", final_blob.len() - 1))
            .body(Body::from(final_blob.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        finalize.headers().get("Range").unwrap(),
        format!("0-{}", stale_blob.len() - 1).as_str()
    );
}

#[tokio::test]
async fn test_delete_upload_returns_204() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let resp = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let uuid = resp
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri(format!("/v2/my-cache/blobs/uploads/{uuid}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_monolithic_upload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_data = b"monolithic blob payload";
    let digest = cas_oci::prefixed_sha256_digest(blob_data);

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v2/my-cache/blobs/uploads/?digest={digest}"))
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );
    assert_eq!(
        response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok()),
        Some(format!("/v2/my-cache/blobs/{digest}").as_str())
    );
}

#[tokio::test]
async fn test_large_monolithic_upload_over_two_megabytes() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_data = vec![b'x'; 3 * 1024 * 1024];
    let digest = cas_oci::prefixed_sha256_digest(&blob_data);

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v2/my-cache/blobs/uploads/?digest={digest}"))
            .body(Body::from(blob_data))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );
    assert_eq!(
        response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok()),
        Some(format!("/v2/my-cache/blobs/{digest}").as_str())
    );
}

#[tokio::test]
async fn test_multi_segment_name_manifest() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":50},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[]);
    let tag = scoped_ref_tag("org/my-cache", "main");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-multi",
                "manifest_url": format!("{}/pointers/entry-multi", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-multi")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/org/my-cache/manifests/main")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("Docker-Content-Digest").is_some());
}

#[tokio::test]
async fn test_multi_segment_name_blob_upload() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/org/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with("/v2/org/my-cache/blobs/uploads/"));
}

#[tokio::test]
async fn test_blob_upload_start_without_trailing_slash() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/org/my-cache/blobs/uploads")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let location = response
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with("/v2/org/my-cache/blobs/uploads/"));
}

#[tokio::test]
async fn test_put_upload_accepts_empty_body_when_blob_already_exists_remote() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": 0
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": blob_digest,
                    "exists": true
                }]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let start_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(start_response.status(), StatusCode::ACCEPTED);
    let uuid = start_response
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/my-cache/blobs/uploads/{uuid}?digest={blob_digest}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        blob_digest
    );
}

#[tokio::test]
async fn test_manifest_put_uses_remote_proof_after_empty_finalize_reuse() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let _empty_finalize_check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": 0
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": blob_digest,
                    "exists": true
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let start_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v2/my-cache/blobs/uploads/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(start_response.status(), StatusCode::ACCEPTED);
    let uuid = start_response
        .headers()
        .get("Docker-Upload-UUID")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let app = build_router(state.clone());
    let finalize_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/my-cache/blobs/uploads/{uuid}?digest={blob_digest}"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finalize_response.status(), StatusCode::CREATED);

    let descriptor_size = 10u64;
    let _descriptor_check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": descriptor_size
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": blob_digest,
                    "exists": true
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let primary_tag = scoped_ref_tag("my-cache", "main");
    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag,
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size,
                "cas_layout": "oci-v1",
                "upload_session_id": "session-entry-primary",
                "manifest_upload_url": format!("{}/uploads/entry-primary-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let blob_stage_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": descriptor_size
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [],
                "already_present": [blob_digest]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;

    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_mock = server
        .mock("GET", primary_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "cache_entry_id": "entry-primary",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_confirm_mock = server
        .mock("PUT", primary_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "3")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": blob_digest,
            "size": descriptor_size
        },
        "layers": []
    })
    .to_string();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    primary_save_mock.assert_async().await;
    blob_stage_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_head_miss_then_upload_publish_clears_blob_negative_cache() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_data = b"blob-present-after-head-miss";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_data);
    let descriptor_size = blob_data.len() as u64;
    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "my-cache",
            &blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-existing".to_string(),
                size_bytes: descriptor_size,
                download_url: None,
                download_url_cached_at: None,
            },
        );
    }

    let remote_miss_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": 0
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": blob_digest,
                    "exists": false
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_miss = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_miss.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        state
            .oci_negative_cache
            .metadata_hints()
            .get("oci_negative_remote_blob_entries")
            .map(String::as_str),
        Some("1")
    );

    let app = build_router(state.clone());
    let upload_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v2/my-cache/blobs/uploads/?digest={blob_digest}"))
            .body(Body::from(blob_data.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(upload_response.status(), StatusCode::CREATED);
    assert!(
        !state
            .oci_negative_cache
            .metadata_hints()
            .contains_key("oci_negative_remote_blob_entries")
    );

    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": blob_digest,
            "size": descriptor_size
        },
        "layers": []
    })
    .to_string();
    let manifest_digest = cas_oci::prefixed_sha256_digest(manifest_body.as_bytes());
    let primary_tag = scoped_ref_tag("my-cache", "main");
    let alias_tag = digest_tag(&manifest_digest);
    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag,
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size,
                "cas_layout": "oci-v1",
                "upload_session_id": "session-entry-primary",
                "manifest_upload_url": format!("{}/uploads/entry-primary-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let blob_stage_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": descriptor_size
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "upload_urls": [],
                "already_present": [blob_digest]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_pointer_mock = server
        .mock("GET", primary_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "cache_entry_id": "entry-primary",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_confirm_mock = server
        .mock("PUT", primary_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "3")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "3",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let alias_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": alias_tag,
                "blob_count": 1,
                "blob_total_size_bytes": descriptor_size
            }
        })))
        .expect(0)
        .create_async()
        .await;
    let alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&alias_tag)
    );
    let alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&alias_tag)
    );
    let alias_pointer_mock = server
        .mock("GET", alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "cache_entry_id": "entry-alias",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let alias_confirm_mock = server
        .mock("PUT", alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "5")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "6",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let publish_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(publish_response.status(), StatusCode::CREATED);
    assert!(
        state
            .upload_sessions
            .read()
            .await
            .find_by_name_and_digest("my-cache", &blob_digest)
            .is_none()
    );

    let app = build_router(state.clone());
    let head_after_publish = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_after_publish.status(), StatusCode::OK);
    assert!(
        state
            .blob_read_cache
            .get_handle(&blob_digest)
            .await
            .is_some()
    );

    remote_miss_mock.assert_async().await;
    primary_save_mock.assert_async().await;
    blob_stage_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    alias_save_mock.assert_async().await;
    alias_pointer_mock.assert_async().await;
    alias_confirm_mock.assert_async().await;
    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics
            .get("oci_engine_negative_cache_hit_remote_blob")
            .map(String::as_str),
        None
    );
}

#[tokio::test]
async fn test_head_remote_blob_check_error_does_not_insert_negative_cache() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "my-cache",
            blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-existing".to_string(),
                size_bytes: 128,
                download_url: None,
                download_url_cached_at: None,
            },
        );
    }

    let remote_check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": blob_digest,
                "size_bytes": 0
            }]
        })))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .expect(3)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        !state
            .oci_negative_cache
            .metadata_hints()
            .contains_key("oci_negative_remote_blob_entries")
    );

    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics
            .get("oci_engine_remote_blob_check_errors")
            .map(String::as_str),
        Some("1")
    );
    assert!(!diagnostics.contains_key("oci_engine_negative_cache_insert_remote_blob"));
    remote_check_mock.assert_async().await;
}

#[tokio::test]
async fn test_blob_proxy_returns_error_on_storage_failure() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 100)]);
    let tag = scoped_ref_tag("img", "v1");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-err",
                "manifest_url": format!("{}/pointers/entry-err", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-err")
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
                    "digest": blob_digest,
                    "url": format!("{}/blobs/{}", server.url(), blob_digest),
                }],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(403)
        .with_body("Forbidden - signed URL expired")
        .create_async()
        .await;

    let app = build_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/img/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");
}

#[tokio::test]
async fn test_blob_proxy_best_effort_returns_404_on_storage_failure() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 100)]);
    let tag = scoped_ref_tag("img", "v1");

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": tag,
                "status": "hit",
                "cache_entry_id": "entry-err",
                "manifest_url": format!("{}/pointers/entry-err", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-err")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": blob_digest,
                    "exists": true
                }]
            })
            .to_string(),
        )
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
                    "digest": blob_digest,
                    "url": format!("{}/blobs/{}", server.url(), blob_digest),
                }],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(403)
        .with_body("Forbidden - signed URL expired")
        .create_async()
        .await;

    let app = build_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/img/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
}

#[tokio::test]
async fn test_cache_registry_best_effort_returns_miss_on_backend_error() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/cache/cache-key-1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

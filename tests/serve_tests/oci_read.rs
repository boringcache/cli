use super::*;

#[tokio::test]
async fn test_nonexistent_route_returns_404() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_unknown_protocol_put_route_returns_not_found() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/unknown-protocol/path")
            .body(Body::from("payload"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_manifest_hit_returns_decoded_index_json() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let blob_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 5000)]);

    let tag = scoped_ref_tag("my-cache", "main");

    let restore_body = json!([{
        "tag": tag,
        "status": "hit",
        "cache_entry_id": "entry-123",
        "manifest_url": format!("{}/pointers/entry-123", server.url()),
        "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
        "storage_mode": "cas",
        "cas_layout": "oci-v1",
    }]);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(restore_body.to_string())
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-123")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_request = json!({
        "cache_entry_id": "entry-123",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_digest, "size_bytes": 5000}
        ]
    });
    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(download_urls_request))
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
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/manifests/main")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["schemaVersion"], 2);
}

#[tokio::test]
async fn test_manifest_misses_when_prefetch_batch_reports_missing_blobs() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let index_json = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let blob_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 5000)]);
    let tag = scoped_ref_tag("my-cache", "main");

    let restore_body = json!([{
        "tag": tag,
        "status": "hit",
        "cache_entry_id": "entry-123",
        "manifest_url": format!("{}/pointers/entry-123", server.url()),
        "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
        "storage_mode": "cas",
        "cas_layout": "oci-v1",
    }]);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(restore_body.to_string())
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-123")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let batch_request = json!({
        "cache_entry_id": "entry-123",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_digest, "size_bytes": 5000}
        ]
    });
    let _download_urls_batch_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(batch_request))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [],
                "missing": [blob_digest]
            })
            .to_string(),
        )
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/manifests/main")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let locator = state.blob_locator.read().await;
    assert!(locator.get("my-cache", blob_digest).is_none());
}

#[tokio::test]
async fn test_manifest_serves_after_verified_blob_storage_preflight_in_best_effort() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, 4096)]);
    let tag = scoped_ref_tag("my-cache", "main");

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
                "cache_entry_id": "entry-storage-miss",
                "manifest_url": format!("{}/pointers/entry-storage-miss", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-storage-miss")
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
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/manifests/main")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let locator = state.blob_locator.read().await;
    let cached = locator.get("my-cache", blob_digest).expect("locator entry");
    let expected_url = format!("{}/blobs/{}", server.url(), blob_digest);
    assert_eq!(cached.cache_entry_id, "entry-storage-miss");
    assert_eq!(cached.download_url.as_deref(), Some(expected_url.as_str()));
}

#[tokio::test]
async fn test_cached_manifest_hit_returns_without_revalidation_in_best_effort() {
    let server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#
            .to_vec();
    let tag = scoped_ref_tag("cached", "v1");
    let manifest_digest = cas_oci::prefixed_sha256_digest(&index_json);
    let cached = Arc::new(OciManifestCacheEntry {
        index_json,
        content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        manifest_digest: manifest_digest.clone(),
        cache_entry_id: "entry-cached-miss".to_string(),
        blobs: vec![boring_cache_cli::api::models::cache::BlobDescriptor {
            digest: blob_digest.to_string(),
            size_bytes: 2048,
        }],
        name: "cached".to_string(),
        inserted_at: Instant::now(),
    });
    state
        .oci_manifest_cache
        .insert(tag.clone(), Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), cached);

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/cached/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.oci_manifest_cache.get(&tag).is_some());
    assert!(
        state
            .oci_manifest_cache
            .get(&digest_tag(&manifest_digest))
            .is_some()
    );
}

#[tokio::test]
async fn test_cached_manifest_hit_keeps_locator_urls() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_content = b"cached-fast-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let blob_size = blob_content.len() as u64;
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#
            .to_vec();
    let tag = scoped_ref_tag("cached-fast", "v2");
    let manifest_digest = cas_oci::prefixed_sha256_digest(&index_json);
    let cached = Arc::new(OciManifestCacheEntry {
        index_json,
        content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        manifest_digest: manifest_digest.clone(),
        cache_entry_id: "entry-cached-fast".to_string(),
        blobs: vec![boring_cache_cli::api::models::cache::BlobDescriptor {
            digest: blob_digest.clone(),
            size_bytes: blob_size,
        }],
        name: "cached-fast".to_string(),
        inserted_at: Instant::now(),
    });
    state
        .oci_manifest_cache
        .insert(tag.clone(), Arc::clone(&cached));
    state
        .oci_manifest_cache
        .insert(digest_tag(&manifest_digest), cached);

    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "cached-fast",
            &blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-cached-fast".to_string(),
                size_bytes: blob_size,
                download_url: Some(format!("{}/blobs/{}", server.url(), blob_digest)),
                download_url_cached_at: Some(Instant::now()),
            },
        );
    }

    let _blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(200)
        .with_body(blob_content)
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let manifest_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/cached-fast/manifests/v2")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(manifest_response.status(), StatusCode::OK);

    let app = build_router(state);
    let blob_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/cached-fast/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(blob_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_blob_get_refreshes_stale_locator_url_after_manifest_return() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let blob_a_content = b"fresh-a";
    let blob_a = cas_oci::prefixed_sha256_digest(blob_a_content);
    let blob_b = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let index_json =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa","size":100},"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[
            (blob_a.as_str(), blob_a_content.len() as u64),
            (blob_b, 2048),
        ],
    );
    let tag = scoped_ref_tag("img", "latest");
    let batch_request = json!({
        "cache_entry_id": "entry-refresh",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_a, "size_bytes": blob_a_content.len() as u64},
            {"digest": blob_b, "size_bytes": 2048}
        ]
    });
    let single_request = json!({
        "cache_entry_id": "entry-refresh",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_a, "size_bytes": blob_a_content.len() as u64}
        ]
    });

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
                "cache_entry_id": "entry-refresh",
                "manifest_url": format!("{}/pointers/entry-refresh", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-refresh")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let _download_urls_batch_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(batch_request))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": blob_a,
                        "url": format!("{}/blobs/stale/{}", server.url(), blob_a),
                    },
                    {
                        "digest": blob_b,
                        "url": format!("{}/blobs/good/{}", server.url(), blob_b),
                    }
                ],
                "missing": [],
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let _download_urls_retry_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(single_request))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [{
                    "digest": blob_a,
                    "url": format!("{}/blobs/fresh/{}", server.url(), blob_a),
                }],
                "missing": [],
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let _stale_blob_mock = server
        .mock("GET", format!("/blobs/stale/{}", blob_a).as_str())
        .with_status(403)
        .with_body("Forbidden - signed URL expired")
        .expect(1)
        .create_async()
        .await;

    let _fresh_blob_mock = server
        .mock("GET", format!("/blobs/fresh/{}", blob_a).as_str())
        .with_status(200)
        .with_body(blob_a_content)
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let manifest_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/img/manifests/latest")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(manifest_response.status(), StatusCode::OK);

    let app = build_router(state);
    let blob_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_a}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(blob_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_manifest_miss_returns_404() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let tag = scoped_ref_tag("my-cache", "nonexistent");
    let restore_body = json!([{
        "tag": tag,
        "status": "miss",
    }]);

    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(restore_body.to_string())
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/my-cache/manifests/nonexistent")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
}

#[tokio::test]
async fn test_manifest_negative_cache_suppresses_repeated_restore_miss() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let tag = scoped_ref_tag("my-cache", "missing");
    let restore_body = json!([{
        "tag": tag,
        "status": "miss",
    }]);

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(restore_body.to_string())
        .create_async()
        .await;

    for _ in 0..2 {
        let response = tower::ServiceExt::oneshot(
            build_router(state.clone()),
            Request::builder()
                .uri("/v2/my-cache/manifests/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    restore_mock.assert_async().await;
    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics
            .get("oci_engine_negative_cache_insert_manifest_ref")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        diagnostics
            .get("oci_engine_negative_cache_hit_manifest_ref")
            .map(String::as_str),
        Some("1")
    );
}

#[tokio::test]
async fn test_manifest_head_returns_headers_no_body() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":50},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[]);
    let tag = scoped_ref_tag("img", "latest");

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
                "cache_entry_id": "entry-456",
                "manifest_url": format!("{}/pointers/entry-456", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-456")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri("/v2/img/manifests/latest")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let manifest_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|value| value.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert_digest_etag(response.headers(), &manifest_digest);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_referrers_route_returns_empty_index_when_missing() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let subject_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let referrers_tag = scoped_ref_tag(
        "my-cache",
        "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let _restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": referrers_tag,
                "status": "miss",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/my-cache/referrers/{subject_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/vnd.oci.image.index.v1+json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["schemaVersion"], 2);
    assert_eq!(
        parsed["mediaType"],
        "application/vnd.oci.image.index.v1+json"
    );
    assert_eq!(parsed["manifests"], json!([]));
}

#[tokio::test]
async fn test_referrers_route_filters_artifact_type() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let subject_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let reference = "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let index_json = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 123,
                "artifactType": "application/vnd.example.sbom.v1",
                "annotations": {
                    "org.example.kind": "sbom"
                }
            },
            {
                "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
                "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "size": 456,
                "artifactType": "application/vnd.example.signature.v1",
                "annotations": {
                    "org.example.kind": "signature"
                }
            }
        ]
    }))
    .unwrap();
    state.oci_manifest_cache.insert(
        scoped_ref_tag("my-cache", reference),
        Arc::new(OciManifestCacheEntry {
            index_json: index_json.clone(),
            content_type: "application/vnd.oci.image.index.v1+json".to_string(),
            manifest_digest: cas_oci::prefixed_sha256_digest(&index_json),
            cache_entry_id: "entry-referrers".to_string(),
            blobs: Vec::new(),
            name: "my-cache".to_string(),
            inserted_at: Instant::now(),
        }),
    );

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!(
                "/v2/my-cache/referrers/{subject_digest}?artifactType=application/vnd.example.signature.v1"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("OCI-Filters-Applied").unwrap(),
        "artifactType"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["manifests"][0]["artifactType"],
        "application/vnd.example.signature.v1"
    );
}

#[tokio::test]
async fn test_referrers_route_rejects_invalid_digest() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri("/v2/my-cache/referrers/not-a-digest")
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
async fn test_blob_unknown_without_manifest_returns_404() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let missing_digest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{missing_digest}"))
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
async fn test_blob_head_and_get_return_local_finalized_upload_session() {
    let server = Server::new_async().await;
    let (state, temp_home, _guard) = setup(&server).await;

    let blob_content = b"local-uploaded-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let temp_path = temp_home.path().join("uploaded-blob");
    tokio::fs::write(&temp_path, blob_content).await.unwrap();

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "upload-local".to_string(),
            name: "my-cache".to_string(),
            temp_path,
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: blob_content.len() as u64,
            finalized_digest: Some(blob_digest.clone()),
            finalized_size: Some(blob_content.len() as u64),
            created_at: Instant::now(),
        });
    }

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(head_response.status(), StatusCode::OK);
    assert_digest_etag(head_response.headers(), &blob_digest);
    assert_eq!(
        head_response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok()),
        Some(blob_content.len().to_string().as_str())
    );

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(get_response.status(), StatusCode::OK);
    assert_digest_etag(get_response.headers(), &blob_digest);
    let body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], blob_content);
}

#[tokio::test]
async fn test_blob_get_range_returns_partial_content_from_local_upload_session() {
    let server = Server::new_async().await;
    let (state, temp_home, _guard) = setup(&server).await;

    let blob_content = b"0123456789abcdef";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let temp_path = temp_home.path().join("uploaded-range-blob");
    tokio::fs::write(&temp_path, blob_content).await.unwrap();

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "upload-range-local".to_string(),
            name: "my-cache".to_string(),
            temp_path,
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(Mutex::new(())),
            bytes_received: blob_content.len() as u64,
            finalized_digest: Some(blob_digest.clone()),
            finalized_size: Some(blob_content.len() as u64),
            created_at: Instant::now(),
        });
    }

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=2-6")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_digest_etag(response.headers(), &blob_digest);
    assert_eq!(response.headers().get("Accept-Ranges").unwrap(), "bytes");
    assert_eq!(
        response.headers().get("Content-Range").unwrap(),
        &format!("bytes 2-6/{}", blob_content.len())
    );
    assert_eq!(response.headers().get("Content-Length").unwrap(), "5");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], &blob_content[2..=6]);
}

#[tokio::test]
async fn test_blob_get_suffix_range_returns_partial_content_from_body_cache() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"suffix-range-body";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    state
        .blob_read_cache
        .insert(&blob_digest, blob_content)
        .await
        .expect("insert blob body");

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=-4")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers().get("Content-Range").unwrap(),
        &format!(
            "bytes {}-{}/{}",
            blob_content.len() - 4,
            blob_content.len() - 1,
            blob_content.len()
        )
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], &blob_content[blob_content.len() - 4..]);
}

#[tokio::test]
async fn test_blob_get_invalid_range_returns_416() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"range-error";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    state
        .blob_read_cache
        .insert(&blob_digest, blob_content)
        .await
        .expect("insert blob body");

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=99-100")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers().get("Content-Range").unwrap(),
        &format!("bytes */{}", blob_content.len())
    );

    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics.get("oci_engine_range_invalid_responses"),
        Some(&"1".to_string())
    );

    let status_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    let body = status_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        status["oci_engine"]["oci_engine_range_invalid_responses"],
        "1"
    );
    assert_eq!(
        status["oci_engine"]["oci_engine_hydration_policy"],
        "metadata-only"
    );
}

#[tokio::test]
async fn test_blob_get_if_range_mismatch_ignores_range() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"if-range-body";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let other_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    state
        .blob_read_cache
        .insert(&blob_digest, blob_content)
        .await
        .expect("insert blob body");

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/my-cache/blobs/{blob_digest}"))
            .header("Range", "bytes=0-3")
            .header("If-Range", format!("\"{other_digest}\""))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("Content-Range").is_none());
    assert_eq!(
        response.headers().get("Content-Length").unwrap(),
        &blob_content.len().to_string()
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], blob_content);
}

#[tokio::test]
async fn test_blob_head_after_manifest_resolution_uses_remote_existence_check() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let blob_size = 23u64;
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(index_json, &[(blob_digest, blob_size)]);
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
                "cache_entry_id": "entry-head-check",
                "manifest_url": format!("{}/pointers/entry-head-check", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-head-check")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_request = json!({
        "cache_entry_id": "entry-head-check",
        "verify_storage": true,
        "blobs": [
            {"digest": blob_digest, "size_bytes": blob_size}
        ]
    });
    let _download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .match_body(Matcher::Json(download_urls_request))
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
        .expect(1)
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
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let manifest_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri("/v2/img/manifests/v1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(manifest_response.status(), StatusCode::OK);

    let app = build_router(state);
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(head_response.status(), StatusCode::OK);
    assert_eq!(
        head_response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok()),
        Some(blob_size.to_string().as_str())
    );
}

#[tokio::test]
async fn test_blob_head_degrades_remote_check_failures_to_404() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "img",
            blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-head-failure".to_string(),
                size_bytes: 42,
                download_url: None,
                download_url_cached_at: None,
            },
        );
    }

    let _check_blobs_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_body(Matcher::Any)
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend failure"}"#)
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_blob_get_after_manifest_resolution() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let blob_content = b"hello blob content";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    let index_json =
        br#"{"schemaVersion":2,"config":{"digest":"sha256:cc","size":10},"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[(blob_digest.as_str(), blob_content.len() as u64)],
    );
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
                "cache_entry_id": "entry-789",
                "manifest_url": format!("{}/pointers/entry-789", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-789")
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
        .with_status(200)
        .with_body(blob_content)
        .expect(1)
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

    let app = build_router(state.clone());
    let first_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(first_response.status(), StatusCode::OK);
    assert_digest_etag(first_response.headers(), &blob_digest);
    assert_eq!(
        first_response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        blob_digest
    );
    assert_eq!(
        first_response.headers().get("Content-Type").unwrap(),
        "application/octet-stream"
    );

    let first_body = first_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&first_body[..], blob_content);

    let app = build_router(state.clone());
    let second_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(second_response.status(), StatusCode::OK);
    assert_digest_etag(second_response.headers(), &blob_digest);
    let second_body = second_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&second_body[..], blob_content);
}

#[tokio::test]
async fn test_blob_get_stream_through_promotes_verified_remote_body() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_OCI_STREAM_THROUGH_MIN_BYTES", "1");

    let blob_content = b"stream-through-remote-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_content);
    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "img",
            &blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-stream-through".to_string(),
                size_bytes: blob_content.len() as u64,
                download_url: Some(format!("{}/blobs/{}", server.url(), blob_digest)),
                download_url_cached_at: Some(Instant::now()),
            },
        );
    }

    let blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(200)
        .with_body(blob_content)
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_digest_etag(response.headers(), &blob_digest);
    assert_eq!(
        response.headers().get("Content-Length").unwrap(),
        &blob_content.len().to_string()
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], blob_content);

    assert!(
        state
            .blob_read_cache
            .get_handle(&blob_digest)
            .await
            .is_some()
    );
    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics.get("oci_engine_stream_through_count"),
        Some(&"1".to_string())
    );
    assert_eq!(
        diagnostics.get("oci_engine_stream_through_bytes"),
        Some(&blob_content.len().to_string())
    );

    let second_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = second_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&second_body[..], blob_content);

    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_blob_get_stream_through_digest_mismatch_cleans_temp_and_skips_cache() {
    let mut server = Server::new_async().await;
    let (state, temp_home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_OCI_STREAM_THROUGH_MIN_BYTES", "1");

    let expected_body = b"aaaaaaaaaaaa";
    let remote_body = b"bbbbbbbbbbbb";
    let blob_digest = cas_oci::prefixed_sha256_digest(expected_body);
    {
        let mut locator = state.blob_locator.write().await;
        locator.insert(
            "img",
            &blob_digest,
            BlobLocatorEntry {
                cache_entry_id: "entry-stream-through-bad-digest".to_string(),
                size_bytes: expected_body.len() as u64,
                download_url: Some(format!("{}/blobs/{}", server.url(), blob_digest)),
                download_url_cached_at: Some(Instant::now()),
            },
        );
    }

    let blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .with_status(200)
        .with_body(remote_body)
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .uri(format!("/v2/img/blobs/{blob_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.into_body().collect().await.is_err());
    assert!(
        state
            .blob_read_cache
            .get_handle(&blob_digest)
            .await
            .is_none()
    );

    let downloads_dir = temp_home.path().join("proxy-runtime/oci-downloads");
    if let Ok(mut entries) = tokio::fs::read_dir(&downloads_dir).await {
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "failed stream-through temp file should be removed"
        );
    }

    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics.get("oci_engine_stream_through_verify_failures"),
        Some(&"1".to_string())
    );
    assert_eq!(
        diagnostics.get("oci_engine_digest_verify_failures"),
        Some(&"1".to_string())
    );

    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_index_manifest_detected_as_index_type() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let index_json = br#"{"schemaVersion":2,"manifests":[{"digest":"sha256:aaa","size":100,"mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"architecture":"amd64","os":"linux"}}]}"#;
    let pointer_bytes = make_pointer(index_json, &[]);
    let tag = scoped_ref_tag("multi", "latest");

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
                "cache_entry_id": "entry-idx",
                "manifest_url": format!("{}/pointers/entry-idx", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_mock = server
        .mock("GET", "/pointers/entry-idx")
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/v2/multi/manifests/latest")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/vnd.oci.image.index.v1+json"
    );
}

#[tokio::test]
async fn test_tag_mapping_deterministic() {
    let t1 = ref_tag("my-cache", "main");
    let t2 = ref_tag("my-cache", "main");
    assert_eq!(t1, t2);
    let prefix = "oci_ref_my-cache__main__";
    assert!(t1.starts_with(prefix));
    let suffix = t1.strip_prefix(prefix).expect("readable ref tag suffix");
    assert_eq!(suffix.len(), 16);
    assert!(suffix.chars().all(|ch| ch.is_ascii_hexdigit()));

    let t3 = ref_tag("my-cache", "dev");
    assert_ne!(t1, t3);

    let dt = digest_tag("sha256:abc123");
    assert_eq!(dt, "oci_digest_abc123");
}

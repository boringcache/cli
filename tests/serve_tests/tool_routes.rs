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
async fn test_sccache_mkcol_is_noop_success() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::from_bytes(b"MKCOL").unwrap())
            .uri("/prefix/0/1/")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_sccache_prefixed_probe_is_noop_success() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/rust/ci/.sccache_check")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_sccache_put_head_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload = b"sccache-payload";
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
                "cache_entry_id": "entry-sccache-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "upload_session_id": "session-entry-sccache-kv",
                "manifest_upload_url": format!("{}/manifest-upload-sccache", server.url()),
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
                    "url": format!("{}/blob-upload-sccache", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-sccache")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-sccache")
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
                "version": "11",
                "cache_entry_id": "entry-sccache-kv",
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
        .match_header("if-match", "11")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "11",
                "status": "confirmed",
                "cache_entry_id": "entry-sccache-kv"
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
            .uri(format!("/{key_path}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::CREATED);

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
                "cache_entry_id": "entry-sccache-kv",
                "manifest_url": format!("{}/pointer-download-sccache", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_head_mock = server
        .mock("GET", "/pointer-download-sccache")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/{key_path}"))
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
                "cache_entry_id": "entry-sccache-kv",
                "manifest_url": format!("{}/pointer-download-sccache-get", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-sccache-get")
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
                    "url": format!("{}/blob-download-sccache", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-sccache")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
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
async fn test_sccache_get_reads_internal_root_tag_only() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.registry_root_tag = "bc_registry_root_v2_root-only".to_string();
    state.configured_human_tags = vec!["human-alias".to_string()];

    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload = b"sccache-root-only";
    let payload_digest = cas_file::prefixed_sha256_digest(payload);
    let pointer_bytes = make_kv_pointer(&[(
        format!("sccache/{key_path}"),
        payload_digest.clone(),
        payload.len() as u64,
    )]);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);
    let root_tag = state.registry_root_tag.clone();
    let root_entries = urlencoding::encode(&root_tag).into_owned();
    let alias_entries = urlencoding::encode("human-alias").into_owned();

    let root_restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(format!(
                "^/v2/workspaces/org/repo/caches\\?entries={root_entries}(&.*)?$"
            )),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": root_tag,
                "status": "hit",
                "cache_entry_id": "entry-sccache-root-only",
                "manifest_url": format!("{}/pointer-download-sccache-root-only", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let alias_restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(format!(
                "^/v2/workspaces/org/repo/caches\\?entries={alias_entries}(&.*)?$"
            )),
        )
        .expect(0)
        .with_status(500)
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointer-download-sccache-root-only")
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
                    "url": format!("{}/blob-download-sccache-root-only", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let blob_download_mock = server
        .mock("GET", "/blob-download-sccache-root-only")
        .expect(1)
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), payload);

    root_restore_mock.assert_async().await;
    alias_restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_download_mock.assert_async().await;
}

#[tokio::test]
async fn test_sccache_concurrent_get_coalesces_blob_download() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload = vec![b'x'; 2 * 1024 * 1024];
    let payload_digest = cas_file::prefixed_sha256_digest(&payload);
    let pointer_bytes = make_kv_pointer(&[(
        format!("sccache/{key_path}"),
        payload_digest.clone(),
        payload.len() as u64,
    )]);
    let pointer_digest = cas_file::prefixed_sha256_digest(&pointer_bytes);

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": "registry",
                "status": "hit",
                "cache_entry_id": "entry-sccache-coalesced",
                "manifest_url": format!("{}/pointer-download-sccache-coalesced", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointer-download-sccache-coalesced")
        .expect_at_least(1)
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
                    "url": format!("{}/blob-download-sccache-coalesced", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let blob_download_mock = server
        .mock("GET", "/blob-download-sccache-coalesced")
        .expect(1)
        .with_status(200)
        .with_body(payload.clone())
        .create_async()
        .await;

    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap()
    };

    let (first, second) = tokio::join!(
        tower::ServiceExt::oneshot(build_router(state.clone()), request()),
        tower::ServiceExt::oneshot(build_router(state), request())
    );

    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);

    let first_body = first.into_body().collect().await.unwrap().to_bytes();
    let second_body = second.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(first_body.as_ref(), payload.as_slice());
    assert_eq!(second_body.as_ref(), payload.as_slice());

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_download_mock.assert_async().await;
}

#[tokio::test]
async fn test_sccache_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let key_path =
        "cache-prefix/0/1/2/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_sccache_head_miss_returns_not_found_without_body() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let key_path =
        "cache-prefix/0/1/2/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty());
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_sccache_miss_is_temporarily_cached_to_reduce_backend_lookups() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key_path = format!(
        "cache-prefix/{}/{}/{}/{}",
        &key[0..1],
        &key[1..2],
        &key[2..3],
        key
    );
    let payload_digest = cas_file::prefixed_sha256_digest(b"unrelated");
    let pointer = cas_file::FilePointer {
        format_version: 1,
        adapter: "file-v1".to_string(),
        entries: vec![cas_file::FilePointerEntry {
            path: "sccache/other-key".to_string(),
            entry_type: EntryType::File,
            size_bytes: 9,
            executable: None,
            target: None,
            digest: Some(payload_digest.clone()),
        }],
        blobs: vec![cas_file::FilePointerBlob {
            digest: payload_digest,
            size_bytes: 9,
            sequence: None,
        }],
    };
    let pointer_bytes = serde_json::to_vec(&pointer).expect("pointer");

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
                "tag": "unused",
                "status": "hit",
                "cache_entry_id": "entry-sccache-kv",
                "manifest_url": format!("{}/pointer-miss-sccache", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointer-miss-sccache")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let first_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(first_response.status(), StatusCode::NOT_FOUND);

    let app = build_router(state);
    let second_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{key_path}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(second_response.status(), StatusCode::NOT_FOUND);

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
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

#[tokio::test]
async fn test_maven_put_get_round_trip() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let cache_key = "v1.1/com.example/app/abcdef1234567890/buildinfo.xml";
    let payload = b"maven-cache-payload";
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
                "cache_entry_id": "entry-maven-kv",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": payload.len(),
                "cas_layout": "file-v1",
                "upload_session_id": "session-entry-maven-kv",
                "manifest_upload_url": format!("{}/manifest-upload-maven", server.url()),
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
                    "url": format!("{}/blob-upload-maven", server.url()),
                    "headers": {}
                }],
                "already_present": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_upload_mock = server
        .mock("PUT", "/blob-upload-maven")
        .match_body(Matcher::Exact(
            String::from_utf8(payload.to_vec()).expect("payload is utf8"),
        ))
        .with_status(200)
        .create_async()
        .await;

    let _manifest_upload_mock = server
        .mock("PUT", "/manifest-upload-maven")
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
                "cache_entry_id": "entry-maven-kv",
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
                "cache_entry_id": "entry-maven-kv"
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
            .uri(format!("/{cache_key}"))
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
                "cache_entry_id": "entry-maven-kv",
                "manifest_url": format!("{}/pointer-download-maven", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock = server
        .mock("GET", "/pointer-download-maven")
        .with_status(200)
        .with_body(pointer_bytes.clone())
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
                    "url": format!("{}/blob-download-maven", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock = server
        .mock("GET", "/blob-download-maven")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/{cache_key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    let _restore_get_mock_second = server
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
                "cache_entry_id": "entry-maven-kv",
                "manifest_url": format!("{}/pointer-download-maven-2", server.url()),
                "manifest_root_digest": pointer_digest,
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let _pointer_get_mock_second = server
        .mock("GET", "/pointer-download-maven-2")
        .with_status(200)
        .with_body(pointer_bytes.clone())
        .create_async()
        .await;

    let _download_urls_mock_second = server
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
                    "url": format!("{}/blob-download-maven-2", server.url())
                }],
                "missing": []
            })
            .to_string(),
        )
        .create_async()
        .await;

    let _blob_download_mock_second = server
        .mock("GET", "/blob-download-maven-2")
        .with_status(200)
        .with_body(payload)
        .create_async()
        .await;

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{cache_key}"))
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
async fn test_maven_put_keeps_generic_spool_rejection_status() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_MAX_SPOOL_BYTES", "1");
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v1.1/com.example/app/abcdef1234567890/buildinfo.xml")
            .body(Body::from("too-large"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_maven_get_and_head_misses_return_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let uri = "/v1.1/com.example/app/abcdef1234567890/buildinfo.xml";

    let get_response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

    let head_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::NOT_FOUND);
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_maven_rejects_unsupported_method() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/v1.1/com.example/app/abcdef1234567890/buildinfo.xml")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_nx_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v1/cache/hash1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_nx_put_head_get_round_trip() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxhash123";
    let payload = b"nx-cache-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", payload.len().to_string())
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
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

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
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
async fn test_nx_artifact_put_returns_conflict_for_existing_record() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxhashconflict";
    let first_payload = b"nx-first-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", first_payload.len().to_string())
            .body(Body::from(first_payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let app = build_router(state.clone());
    let conflict_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", "14")
            .body(Body::from("second-payload"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(conflict_response.status(), StatusCode::CONFLICT);

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), first_payload);
}

#[tokio::test]
async fn test_nx_query_returns_misses() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxtaskhash1";
    let payload = b"nx-query-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", payload.len().to_string())
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);
    {
        let mut published = state.kv_published_index.write().await;
        published.set_empty();
    }

    let app = build_router(state);
    let query_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v1/cache")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": [hash, "deadbeef"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(query_response.status(), StatusCode::OK);
    let body = query_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["misses"], json!(["deadbeef"]));
}

#[tokio::test]
async fn test_nx_artifact_get_miss_returns_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri("/v1/cache/missinghash")
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
async fn test_nx_terminal_output_get_and_head_misses_return_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let uri = "/v1/cache/missinghash/terminalOutputs";

    let get_response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

    let head_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::NOT_FOUND);
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_go_cache_put_head_get_round_trip() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let action = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let payload = b"go-cache-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/gocache/{action}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::CREATED);

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/gocache/{action}"))
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

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/gocache/{action}"))
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
async fn test_go_cache_get_miss_returns_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let action = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/gocache/{action}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_go_cache_rejects_invalid_action_id() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/gocache/not-hex")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

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

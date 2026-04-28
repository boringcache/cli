use super::*;

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

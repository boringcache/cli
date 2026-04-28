use super::*;

#[tokio::test]
async fn test_startup_manifest_warm_runs_by_default() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        vec!["main".to_string()],
        "registry".to_string(),
        Vec::new(),
        BTreeMap::new(),
        true,
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();

    wait_for_prefetch_state(&client, &base_url, "ready").await;

    handle.shutdown_and_flush().await.expect("shutdown proxy");
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_command_proxy_start_continues_when_warmup_fails() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;
    test_env::set_var("BORINGCACHE_SAVE_TOKEN", "test-token");

    let restore_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .expect_at_least(1)
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"boom"}"#)
        .create_async()
        .await;

    let handle = boring_cache_cli::commands::cache_registry::start_proxy_background(
        "org/repo".to_string(),
        "main".to_string(),
        "127.0.0.1".to_string(),
        0,
        false,
        false,
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        None,
        BTreeMap::new(),
        true,
        true,
        false,
        Vec::new(),
    )
    .await
    .expect("start proxy");

    handle.shutdown_and_flush().await.expect("shutdown proxy");
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_v2_returns_200_with_warming_header_before_prefetch_complete() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder().uri("/v2/").body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Prefetch-State")
            .unwrap(),
        "warming"
    );
}

#[tokio::test]
async fn test_kv_reads_wait_for_startup_prefetch_completion() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);

    let payload = b"warm-local-payload";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("blob cache insert");
    {
        let mut published = state.kv_published_index.write().await;
        published.update(
            std::collections::HashMap::from([(
                "gradle/cache-key-1".to_string(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: payload.len() as u64,
                },
            )]),
            vec![BlobDescriptor {
                digest: digest.clone(),
                size_bytes: payload.len() as u64,
            }],
            "entry-prefetched".to_string(),
        );
    }

    let app = build_router(state.clone());
    let request_task = tokio::spawn(async move {
        tower::ServiceExt::oneshot(
            app,
            Request::builder()
                .uri("/foo/cache/cache-key-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request")
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !request_task.is_finished(),
        "KV GET should wait while startup prefetch is still warming"
    );

    state
        .prefetch_complete
        .store(true, std::sync::atomic::Ordering::Release);
    state.prefetch_complete_notify.notify_waiters();

    let response = request_task.await.expect("join");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_startup_prefetch_hydrates_full_tag_before_ready() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let warm_blob_a = b"aaaaa";
    let warm_blob_b = b"bbbbb";
    let cold_blob = b"cccccccccccc";
    let digest_a = cas_oci::prefixed_sha256_digest(warm_blob_a);
    let digest_b = cas_oci::prefixed_sha256_digest(warm_blob_b);
    let digest_c = cas_oci::prefixed_sha256_digest(cold_blob);

    let key_a = digest_a.strip_prefix("sha256:").unwrap();
    let key_b = digest_b.strip_prefix("sha256:").unwrap();
    let key_c = digest_c.strip_prefix("sha256:").unwrap();
    let pointer_entries = vec![
        (
            format!("bazel_cas/{key_a}"),
            digest_a.clone(),
            warm_blob_a.len() as u64,
        ),
        (
            format!("bazel_cas/{key_b}"),
            digest_b.clone(),
            warm_blob_b.len() as u64,
        ),
        (
            format!("bazel_cas/{key_c}"),
            digest_c.clone(),
            cold_blob.len() as u64,
        ),
    ];
    let pointer_bytes = make_kv_pointer(&pointer_entries);

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
                "cache_entry_id": "entry-full-hydration",
                "manifest_url": format!("{}/pointers/entry-full-hydration", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-full-hydration")
        .expect_at_least(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect_at_least(1)
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": digest_a,
                        "url": format!("{}/blobs/{}", server.url(), digest_a),
                    },
                    {
                        "digest": digest_b,
                        "url": format!("{}/blobs/{}", server.url(), digest_b),
                    },
                    {
                        "digest": digest_c,
                        "url": format!("{}/blobs/{}", server.url(), digest_c),
                    }
                ],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let warm_blob_a_mock = server
        .mock("GET", format!("/blobs/{}", digest_a).as_str())
        .expect(1)
        .with_status(200)
        .with_body(warm_blob_a)
        .create_async()
        .await;
    let warm_blob_b_mock = server
        .mock("GET", format!("/blobs/{}", digest_b).as_str())
        .expect(1)
        .with_status(200)
        .with_body(warm_blob_b)
        .create_async()
        .await;
    let cold_blob_mock = server
        .mock("GET", format!("/blobs/{}", digest_c).as_str())
        .expect(1)
        .with_status(200)
        .with_body(cold_blob)
        .create_async()
        .await;
    let pointer_visibility_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .expect(0)
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        Vec::new(),
        "registry".to_string(),
        Vec::new(),
        BTreeMap::new(),
        true,
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();

    wait_for_prefetch_state(&client, &base_url, "ready").await;

    warm_blob_a_mock.assert_async().await;
    warm_blob_b_mock.assert_async().await;
    cold_blob_mock.assert_async().await;

    let blob_response = client
        .get(format!("{base_url}/cas/{key_c}"))
        .send()
        .await
        .expect("blob request");
    assert_eq!(blob_response.status(), reqwest::StatusCode::OK);
    assert_eq!(blob_response.bytes().await.unwrap().as_ref(), cold_blob);

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    pointer_visibility_mock.assert_async().await;
}

#[tokio::test]
async fn test_startup_prefetch_partial_blob_failure_does_not_block_readiness() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let warm_blob = b"warm";
    let cold_blob = b"cold";
    let warm_digest = cas_oci::prefixed_sha256_digest(warm_blob);
    let cold_digest = cas_oci::prefixed_sha256_digest(cold_blob);
    let warm_key = warm_digest.strip_prefix("sha256:").unwrap();
    let cold_key = cold_digest.strip_prefix("sha256:").unwrap();
    let pointer_entries = vec![
        (
            format!("bazel_cas/{warm_key}"),
            warm_digest.clone(),
            warm_blob.len() as u64,
        ),
        (
            format!("bazel_cas/{cold_key}"),
            cold_digest.clone(),
            cold_blob.len() as u64,
        ),
    ];
    let pointer_bytes = make_kv_pointer(&pointer_entries);
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
                "cache_entry_id": "entry-partial-hydration",
                "manifest_url": format!("{}/pointers/entry-partial-hydration", server.url()),
                "manifest_root_digest": cas_file::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "file-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-partial-hydration")
        .expect_at_least(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect_at_least(1)
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "download_urls": [
                    {
                        "digest": warm_digest,
                        "url": format!("{}/blobs/{}", server.url(), warm_digest),
                    },
                    {
                        "digest": cold_digest,
                        "url": format!("{}/blobs/{}", server.url(), cold_digest),
                    }
                ],
                "missing": [],
            })
            .to_string(),
        )
        .create_async()
        .await;

    let warm_blob_mock = server
        .mock("GET", format!("/blobs/{}", warm_digest).as_str())
        .expect_at_least(1)
        .with_status(200)
        .with_body(warm_blob)
        .create_async()
        .await;
    let cold_blob_mock = server
        .mock("GET", format!("/blobs/{}", cold_digest).as_str())
        .expect_at_least(1)
        .with_status(500)
        .with_body("temporary backend failure")
        .create_async()
        .await;
    let pointer_visibility_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::to_string(&json!({
                "tag": "registry",
                "cache_entry_id": "entry-partial-hydration",
                "manifest_root_digest": pointer_digest,
                "version": "1"
            }))
            .unwrap(),
        )
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        Vec::new(),
        "registry".to_string(),
        Vec::new(),
        BTreeMap::new(),
        true,
        Vec::new(),
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        false,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();
    wait_for_prefetch_state(&client, &base_url, "ready").await;

    let response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let status: serde_json::Value = response.json().await.expect("status json");
    assert_eq!(status["phase"], "ready");
    assert_eq!(status["prefetch_complete"], true);
    assert!(status["prefetch_error"].is_null());
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_total_unique_blobs"],
        "2"
    );
    assert_eq!(status["startup_prefetch"]["startup_prefetch_inserted"], "1");
    assert_eq!(status["startup_prefetch"]["startup_prefetch_failures"], "1");
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_cold_blobs"],
        "1"
    );

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    warm_blob_mock.assert_async().await;
    cold_blob_mock.assert_async().await;
    pointer_visibility_mock.assert_async().await;
}

#[tokio::test]
async fn test_oci_prefetch_ref_indexes_manifest_before_ready() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let blob_payload = b"oci-prefetched-blob";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_payload);
    let index_json = br#"{"schemaVersion":2,"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[(blob_digest.as_str(), blob_payload.len() as u64)],
    );
    let oci_tag = scoped_ref_tag("img", "v1");
    let legacy_oci_tag = legacy_scoped_ref_tag("img", "v1");
    let oci_entries_input = format!("{oci_tag},{legacy_oci_tag}");
    let oci_entries = urlencoding::encode(&oci_entries_input);

    let oci_restore_mock = server
        .mock(
            "GET",
            format!("/v2/workspaces/org/repo/caches?entries={oci_entries}").as_str(),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": oci_tag,
                "status": "hit",
                "cache_entry_id": "entry-oci-prefetch",
                "manifest_url": format!("{}/pointers/entry-oci-prefetch", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let kv_restore_mock = server
        .mock("GET", "/v2/workspaces/org/repo/caches?entries=registry")
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-oci-prefetch")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(1)
        .match_body(Matcher::Any)
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

    let blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .expect(1)
        .with_status(200)
        .with_body(blob_payload)
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        Vec::new(),
        "registry".to_string(),
        Vec::new(),
        BTreeMap::new(),
        true,
        vec![("img".to_string(), "v1".to_string())],
        boring_cache_cli::serve::OciHydrationPolicy::MetadataOnly,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();
    wait_for_prefetch_state(&client, &base_url, "ready").await;

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request");
    assert_eq!(status_response.status(), reqwest::StatusCode::OK);
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(status["startup_prefetch"]["startup_prefetch_oci_refs"], "1");
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_total_unique_blobs"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_hydration"],
        "metadata-only"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_inserted"],
        "0"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_cold_blobs"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_body_cold_blobs"],
        "1"
    );

    let response = client
        .get(format!("{base_url}/v2/img/blobs/{blob_digest}"))
        .send()
        .await
        .expect("blob request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), blob_payload);

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request after blob read");
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(status["oci_body"]["oci_body_remote_fetches"], "1");
    assert_eq!(status["oci_body"]["oci_body_local_hits"], "0");

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    oci_restore_mock.assert_async().await;
    kv_restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_oci_prefetch_ref_can_hydrate_bodies_before_ready() {
    let mut server = Server::new_async().await;
    let (_state, _home, _guard) = setup(&server).await;

    let blob_payload = b"oci-prefetched-blob-ready";
    let blob_digest = cas_oci::prefixed_sha256_digest(blob_payload);
    let index_json = br#"{"schemaVersion":2,"layers":[]}"#;
    let pointer_bytes = make_pointer(
        index_json,
        &[(blob_digest.as_str(), blob_payload.len() as u64)],
    );
    let oci_tag = scoped_ref_tag("img", "v1");
    let legacy_oci_tag = legacy_scoped_ref_tag("img", "v1");
    let oci_entries_input = format!("{oci_tag},{legacy_oci_tag}");
    let oci_entries = urlencoding::encode(&oci_entries_input);

    let oci_restore_mock = server
        .mock(
            "GET",
            format!("/v2/workspaces/org/repo/caches?entries={oci_entries}").as_str(),
        )
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": oci_tag,
                "status": "hit",
                "cache_entry_id": "entry-oci-prefetch-ready",
                "manifest_url": format!("{}/pointers/entry-oci-prefetch-ready", server.url()),
                "manifest_root_digest": cas_oci::prefixed_sha256_digest(&pointer_bytes),
                "storage_mode": "cas",
                "cas_layout": "oci-v1",
            }])
            .to_string(),
        )
        .create_async()
        .await;

    let kv_restore_mock = server
        .mock("GET", "/v2/workspaces/org/repo/caches?entries=registry")
        .expect_at_least(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;

    let pointer_mock = server
        .mock("GET", "/pointers/entry-oci-prefetch-ready")
        .expect(1)
        .with_status(200)
        .with_body(pointer_bytes)
        .create_async()
        .await;

    let download_urls_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/download-urls")
        .expect(1)
        .match_body(Matcher::Any)
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

    let blob_mock = server
        .mock("GET", format!("/blobs/{}", blob_digest).as_str())
        .expect(1)
        .with_status(200)
        .with_body(blob_payload)
        .create_async()
        .await;

    let handle = boring_cache_cli::serve::start_server_background(
        ApiClient::new_with_token_override(Some("test-token".to_string())).expect("api client"),
        "org/repo".to_string(),
        "127.0.0.1".to_string(),
        0,
        TagResolver::new(None, GitContext::default(), false),
        Vec::new(),
        "registry".to_string(),
        Vec::new(),
        BTreeMap::new(),
        true,
        vec![("img".to_string(), "v1".to_string())],
        boring_cache_cli::serve::OciHydrationPolicy::BodiesBeforeReady,
        true,
        false,
    )
    .await
    .expect("start proxy");

    let base_url = format!("http://127.0.0.1:{}", handle.port);
    let client = reqwest::Client::new();
    wait_for_prefetch_state(&client, &base_url, "ready").await;

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request");
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_hydration"],
        "bodies-before-ready"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_inserted"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_cold_blobs"],
        "0"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_body_inserted"],
        "1"
    );
    assert_eq!(
        status["startup_prefetch"]["startup_prefetch_oci_body_cold_blobs"],
        "0"
    );

    let response = client
        .get(format!("{base_url}/v2/img/blobs/{blob_digest}"))
        .send()
        .await
        .expect("blob request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), blob_payload);

    let status_response = client
        .get(format!("{base_url}/_boringcache/status"))
        .send()
        .await
        .expect("status request after blob read");
    let status: serde_json::Value = status_response.json().await.expect("status json");
    assert_eq!(status["oci_body"]["oci_body_local_hits"], "1");
    assert_eq!(status["oci_body"]["oci_body_remote_fetches"], "0");

    handle.shutdown_and_flush().await.expect("shutdown proxy");

    oci_restore_mock.assert_async().await;
    kv_restore_mock.assert_async().await;
    pointer_mock.assert_async().await;
    download_urls_mock.assert_async().await;
    blob_mock.assert_async().await;
}

#[tokio::test]
async fn test_v2_base_returns_200() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder().uri("/v2/").body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Distribution-API-Version")
            .unwrap(),
        "registry/2.0"
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Prefetch-State")
            .unwrap(),
        "ready"
    );
}

#[tokio::test]
async fn test_proxy_status_reports_warming_phase() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("warming")
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Publish-State")
            .and_then(|value| value.to_str().ok()),
        Some("settled")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "warming");
    assert_eq!(status["publish_state"], "settled");
    assert_eq!(status["publish_settled"], true);
    assert_eq!(status["pending_entries"], 0);
    assert_eq!(status["flush_in_progress"], false);
}

#[tokio::test]
async fn test_proxy_status_reports_error_phase() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .prefetch_complete
        .store(false, std::sync::atomic::Ordering::Release);
    {
        let mut prefetch_error = state.prefetch_error.write().await;
        *prefetch_error = Some("cache index load failed".to_string());
    }
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("error")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "error");
    assert_eq!(status["prefetch_error"], "cache index load failed");
    assert_eq!(status["prefetch_complete"], false);
}

#[tokio::test]
async fn test_proxy_status_reports_pending_when_entries_buffered() {
    let server = Server::new_async().await;
    let (state, home, _guard) = setup(&server).await;
    let temp_path = home.path().join("pending-blob.bin");
    tokio::fs::write(&temp_path, b"pending-bytes")
        .await
        .expect("write pending blob");
    {
        let mut pending = state.kv_pending.write().await;
        pending.insert(
            "cas/example".to_string(),
            BlobDescriptor {
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size_bytes: 13,
            },
            temp_path,
        );
    }
    let app = build_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("ready")
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Publish-State")
            .and_then(|value| value.to_str().ok()),
        Some("pending")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "ready");
    assert_eq!(status["publish_settled"], false);
    assert_eq!(status["pending_entries"], 1);
    assert_eq!(status["pending_blobs"], 1);
}

#[tokio::test]
async fn test_proxy_status_reports_diagnostic_tag_visibility_while_draining() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    state
        .shutdown_requested
        .store(true, std::sync::atomic::Ordering::Release);
    {
        let mut published = state.kv_published_index.write().await;
        published.update(
            std::collections::HashMap::new(),
            Vec::new(),
            "entry-123".to_string(),
        );
    }

    let _pointer_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches/tags/registry/pointer".to_string()),
        )
        .with_status(404)
        .create_async()
        .await;

    let app = build_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .uri("/_boringcache/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Proxy-Phase")
            .and_then(|value| value.to_str().ok()),
        Some("draining")
    );
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Publish-State")
            .and_then(|value| value.to_str().ok()),
        Some("pending")
    );

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["phase"], "draining");
    assert_eq!(status["cache_entry_id"], "entry-123");
    assert_eq!(status["tags_visible"], false);
    assert_eq!(status["publish_settled"], false);
}

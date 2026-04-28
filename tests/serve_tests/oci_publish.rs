use super::*;

#[tokio::test]
async fn test_manifest_put_confirms_alias_when_alias_save_exists() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");
    let alias_tag = digest_tag(&manifest_digest);
    let legacy_alias_tag = legacy_scoped_ref_tag("my-cache", "main");

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
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
                "blob_count": 0,
                "blob_total_size_bytes": 0,
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
                "tag": alias_tag
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
    let legacy_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&legacy_alias_tag)
    );
    let legacy_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&legacy_alias_tag)
    );
    let legacy_alias_pointer_mock = server
        .mock("GET", legacy_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "cache_entry_id": "entry-legacy-alias",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let legacy_alias_confirm_mock = server
        .mock("PUT", legacy_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "7")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas",
            "write_scope_tag": "my-cache:main"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "8",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let manifest_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|value| value.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert_digest_etag(response.headers(), &manifest_digest);
    assert_eq!(
        response
            .headers()
            .get("Docker-Distribution-API-Version")
            .unwrap(),
        "registry/2.0"
    );

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    alias_save_mock.assert_async().await;
    alias_pointer_mock.assert_async().await;
    alias_confirm_mock.assert_async().await;
    legacy_alias_pointer_mock.assert_async().await;
    legacy_alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_degrades_when_primary_confirm_is_locked() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let primary_tag = scoped_ref_tag("my-cache", "main");

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
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
                "blob_count": 0,
                "blob_total_size_bytes": 0,
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
        .with_status(423)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "tag is locked",
                "message": "tag is locked",
                "code": "tag_locked"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let manifest_digest = response
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|value| value.to_str().ok())
        .expect("Docker-Content-Digest header")
        .to_string();
    assert_digest_etag(response.headers(), &manifest_digest);
    assert_eq!(
        response
            .headers()
            .get("X-BoringCache-Cache-Degraded")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_skips_alias_when_confirm_is_locked() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");
    let alias_tag = digest_tag(&manifest_digest);

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
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
                "blob_count": 0,
                "blob_total_size_bytes": 0,
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
                "tag": alias_tag
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
        .with_status(423)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "error": "tag is locked",
                "message": "tag is locked",
                "code": "tag_locked"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        response
            .headers()
            .get("X-BoringCache-Cache-Degraded")
            .is_none()
    );

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    alias_save_mock.assert_async().await;
    alias_pointer_mock.assert_async().await;
    alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_two_immutable_run_refs_promote_same_alias_without_losing_roots() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.oci_alias_promotion_refs = vec!["branch-main".to_string()];

    struct PublishCase {
        reference: &'static str,
        manifest_body: Vec<u8>,
        primary_tag: String,
    }

    let branch_alias_tag = scoped_ref_tag("cache", "branch-main");
    let branch_legacy_alias_tag = legacy_scoped_ref_tag("cache", "branch-main");
    let branch_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&branch_alias_tag)
    );
    let mut mocks = vec![
        server
            .mock("GET", branch_pointer_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": "branch-version",
                    "cache_entry_id": "entry-branch-current",
                    "status": "ready"
                })
                .to_string(),
            )
            .expect(2)
            .create_async()
            .await,
    ];
    let mut cases = Vec::new();

    for (reference, entry_prefix, branch_status, branch_reason) in [
        ("run-a", "entry-run-a", "promoted", "accepted"),
        (
            "run-b",
            "entry-run-b",
            "ignored_stale",
            "newer_run_already_promoted",
        ),
    ] {
        let manifest_body = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "annotations": {
                "org.opencontainers.image.ref.name": reference
            }
        }))
        .unwrap();
        let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
        let manifest_root_digest =
            cas_oci::prefixed_sha256_digest(&make_oci_publish_pointer(&manifest_body));
        let primary_tag = scoped_ref_tag("cache", reference);
        let primary_legacy_alias_tag = legacy_scoped_ref_tag("cache", reference);
        let digest_alias_tag = digest_tag(&manifest_digest);

        let primary_save_mock = server
            .mock("POST", "/v2/workspaces/org/repo/caches")
            .match_header("authorization", "Bearer test-token")
            .match_body(Matcher::PartialJson(json!({
                "cache": {
                    "tag": primary_tag,
                    "manifest_root_digest": manifest_root_digest
                }
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "tag": primary_tag,
                    "cache_entry_id": entry_prefix,
                    "exists": false,
                    "storage_mode": "cas",
                    "blob_count": 1,
                    "blob_total_size_bytes": 1,
                    "cas_layout": "oci-v1",
                    "upload_session_id": format!("session-{entry_prefix}"),
                    "manifest_upload_url": format!("{}/uploads/{entry_prefix}-manifest", server.url()),
                    "archive_urls": [],
                    "upload_headers": {}
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(primary_save_mock);

        let pointer_upload_mock = server
            .mock("PUT", format!("/uploads/{entry_prefix}-manifest").as_str())
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        mocks.push(pointer_upload_mock);

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
                    "version": format!("{entry_prefix}-primary-version"),
                    "cache_entry_id": entry_prefix,
                    "status": "ready"
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(primary_pointer_mock);

        let primary_publish_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/publish",
            urlencoding::encode(&primary_tag)
        );
        let primary_confirm_mock = server
            .mock("PUT", primary_publish_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .match_body(Matcher::PartialJson(json!({
                "cache_entry_id": entry_prefix,
                "cache": {
                    "manifest_digest": manifest_root_digest
                }
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("{entry_prefix}-primary-version"),
                    "status": "ok",
                    "cache_entry_id": entry_prefix
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(primary_confirm_mock);

        let digest_alias_save_mock = server
            .mock("POST", "/v2/workspaces/org/repo/caches")
            .match_header("authorization", "Bearer test-token")
            .match_body(Matcher::PartialJson(json!({
                "cache": {
                    "tag": digest_alias_tag,
                    "manifest_root_digest": manifest_root_digest
                }
            })))
            .expect(0)
            .create_async()
            .await;
        mocks.push(digest_alias_save_mock);

        let digest_pointer_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/pointer",
            urlencoding::encode(&digest_alias_tag)
        );
        let digest_pointer_mock = server
            .mock("GET", digest_pointer_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("{entry_prefix}-digest-version"),
                    "cache_entry_id": format!("{entry_prefix}-digest-current"),
                    "status": "ready"
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(digest_pointer_mock);

        let digest_publish_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/publish",
            urlencoding::encode(&digest_alias_tag)
        );
        let digest_alias_confirm_mock = server
            .mock("PUT", digest_publish_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .match_header(
                "if-match",
                format!("{entry_prefix}-digest-version").as_str(),
            )
            .match_body(Matcher::PartialJson(json!({
                "cache_entry_id": entry_prefix,
                "publish_mode": "cas"
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("{entry_prefix}-digest-version"),
                    "status": "ok",
                    "cache_entry_id": entry_prefix,
                    "promotion_status": "unchanged",
                    "requested_cache_entry_id": entry_prefix
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(digest_alias_confirm_mock);

        let primary_legacy_alias_pointer_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/pointer",
            urlencoding::encode(&primary_legacy_alias_tag)
        );
        let primary_legacy_alias_pointer_mock = server
            .mock("GET", primary_legacy_alias_pointer_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("{entry_prefix}-legacy-version"),
                    "cache_entry_id": format!("{entry_prefix}-legacy-current"),
                    "status": "ready"
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(primary_legacy_alias_pointer_mock);

        let primary_legacy_alias_publish_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/publish",
            urlencoding::encode(&primary_legacy_alias_tag)
        );
        let primary_legacy_alias_confirm_mock = server
            .mock("PUT", primary_legacy_alias_publish_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .match_header(
                "if-match",
                format!("{entry_prefix}-legacy-version").as_str(),
            )
            .match_body(Matcher::PartialJson(json!({
                "cache_entry_id": entry_prefix,
                "write_scope_tag": format!("cache:{reference}"),
                "publish_mode": "cas"
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("{entry_prefix}-legacy-version"),
                    "status": "ok",
                    "cache_entry_id": entry_prefix,
                    "promotion_status": "unchanged",
                    "requested_cache_entry_id": entry_prefix
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(primary_legacy_alias_confirm_mock);

        let branch_alias_save_mock = server
            .mock("POST", "/v2/workspaces/org/repo/caches")
            .match_header("authorization", "Bearer test-token")
            .match_body(Matcher::PartialJson(json!({
                "cache": {
                    "tag": branch_alias_tag,
                    "write_scope_tag": "cache:branch-main",
                    "manifest_root_digest": manifest_root_digest
                }
            })))
            .expect(0)
            .create_async()
            .await;
        mocks.push(branch_alias_save_mock);

        let branch_publish_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/publish",
            urlencoding::encode(&branch_alias_tag)
        );
        let branch_alias_confirm_mock = server
            .mock("PUT", branch_publish_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .match_header("if-match", "branch-version")
            .match_body(Matcher::PartialJson(json!({
                "cache_entry_id": entry_prefix,
                "write_scope_tag": "cache:branch-main",
                "publish_mode": "cas"
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": "branch-version",
                    "status": "ok",
                    "cache_entry_id": entry_prefix,
                    "promotion_status": branch_status,
                    "promotion_reason": branch_reason,
                    "requested_cache_entry_id": entry_prefix
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(branch_alias_confirm_mock);

        let branch_legacy_alias_pointer_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/pointer",
            urlencoding::encode(&branch_legacy_alias_tag)
        );
        let branch_legacy_alias_pointer_mock = server
            .mock("GET", branch_legacy_alias_pointer_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("branch-legacy-version-{entry_prefix}"),
                    "cache_entry_id": "entry-branch-legacy-current",
                    "status": "ready"
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(branch_legacy_alias_pointer_mock);

        let branch_legacy_alias_publish_path = format!(
            "/v2/workspaces/org/repo/caches/tags/{}/publish",
            urlencoding::encode(&branch_legacy_alias_tag)
        );
        let branch_legacy_alias_confirm_mock = server
            .mock("PUT", branch_legacy_alias_publish_path.as_str())
            .match_header("authorization", "Bearer test-token")
            .match_header(
                "if-match",
                format!("branch-legacy-version-{entry_prefix}").as_str(),
            )
            .match_body(Matcher::PartialJson(json!({
                "cache_entry_id": entry_prefix,
                "write_scope_tag": "cache:branch-main",
                "publish_mode": "cas"
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "version": format!("branch-legacy-version-{entry_prefix}"),
                    "status": "ok",
                    "cache_entry_id": entry_prefix,
                    "promotion_status": "unchanged",
                    "requested_cache_entry_id": entry_prefix
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;
        mocks.push(branch_legacy_alias_confirm_mock);

        cases.push(PublishCase {
            reference,
            manifest_body,
            primary_tag,
        });
    }

    let publish_a = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/cache/manifests/{}", cases[0].reference))
            .body(Body::from(cases[0].manifest_body.clone()))
            .unwrap(),
    );
    let publish_b = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/cache/manifests/{}", cases[1].reference))
            .body(Body::from(cases[1].manifest_body.clone()))
            .unwrap(),
    );
    let (response_a, response_b) = tokio::join!(publish_a, publish_b);
    assert_eq!(response_a.unwrap().status(), StatusCode::CREATED);
    assert_eq!(response_b.unwrap().status(), StatusCode::CREATED);

    for case in &cases {
        let response = tower::ServiceExt::oneshot(
            build_router(state.clone()),
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v2/cache/manifests/{}", case.reference))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), case.manifest_body.as_slice());
        assert!(
            state.oci_manifest_cache.get(&case.primary_tag).is_some(),
            "primary run ref {} should stay cached",
            case.reference
        );
    }

    for mock in mocks {
        mock.assert_async().await;
    }

    let diagnostics = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    assert_eq!(
        diagnostics
            .get("oci_engine_alias_promotion_promoted")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        diagnostics
            .get("oci_engine_alias_promotion_ignored_stale")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        diagnostics
            .get("oci_engine_alias_promotion_unchanged")
            .map(String::as_str),
        Some("6")
    );
    assert_eq!(
        diagnostics
            .get("oci_engine_alias_promotion_failed")
            .map(String::as_str),
        None
    );
}

#[tokio::test]
async fn test_manifest_put_with_subject_emits_oci_subject_and_serves_referrers() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let subject_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let manifest_body = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
        "artifactType": "application/vnd.example.sbom.v1",
        "blobs": [],
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": subject_digest,
            "size": 123
        },
        "annotations": {
            "org.example.kind": "sbom"
        }
    }))
    .unwrap();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = scoped_ref_tag("my-cache", "main");

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": primary_tag,
                "cache_entry_id": "entry-primary-subject",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "upload_session_id": "session-entry-primary-subject",
                "manifest_upload_url": format!("{}/uploads/entry-primary-subject-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let primary_pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-primary-subject-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let primary_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&primary_tag)
    );
    let primary_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
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
                "cache_entry_id": "entry-primary-subject",
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
                "cache_entry_id": "entry-primary-subject"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let referrers_reference =
        "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let referrers_tag = scoped_ref_tag("my-cache", referrers_reference);
    let referrers_restore_miss_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"^/v2/workspaces/org/repo/caches\?entries=.*".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!([{
                "tag": referrers_tag,
                "status": "miss"
            }])
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let referrers_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": referrers_tag
            }
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag": referrers_tag,
                "cache_entry_id": "entry-referrers",
                "exists": false,
                "storage_mode": "cas",
                "blob_count": 0,
                "blob_total_size_bytes": 0,
                "cas_layout": "oci-v1",
                "upload_session_id": "session-entry-referrers",
                "manifest_upload_url": format!("{}/uploads/entry-referrers-manifest", server.url()),
                "archive_urls": [],
                "upload_headers": {}
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let referrers_pointer_upload_mock = server
        .mock("PUT", "/uploads/entry-referrers-manifest")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let referrers_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&referrers_tag)
    );
    let referrers_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&referrers_tag)
    );
    let referrers_pointer_mock = server
        .mock("GET", referrers_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "cache_entry_id": "entry-referrers",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let referrers_confirm_mock = server
        .mock("PUT", referrers_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "7")
        .match_body(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "status": "ok",
                "cache_entry_id": "entry-referrers"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header(
                "Content-Type",
                "application/vnd.oci.artifact.manifest.v1+json",
            )
            .body(Body::from(manifest_body.clone()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers().get("OCI-Subject").unwrap(),
        subject_digest
    );
    assert!(
        response
            .headers()
            .get("X-BoringCache-Cache-Degraded")
            .is_none()
    );

    let referrers_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/my-cache/referrers/{subject_digest}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(referrers_response.status(), StatusCode::OK);
    let body = referrers_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(
        parsed["manifests"][0]["digest"],
        serde_json::Value::String(manifest_digest)
    );
    assert_eq!(
        parsed["manifests"][0]["artifactType"],
        "application/vnd.example.sbom.v1"
    );
    assert_eq!(
        parsed["manifests"][0]["annotations"]["org.example.kind"],
        "sbom"
    );

    primary_save_mock.assert_async().await;
    primary_pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    referrers_restore_miss_mock.assert_async().await;
    referrers_save_mock.assert_async().await;
    referrers_pointer_upload_mock.assert_async().await;
    referrers_pointer_mock.assert_async().await;
    referrers_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_by_digest_binds_latest_alias() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = digest_tag(&manifest_digest);
    let latest_alias_tag = scoped_ref_tag("my-cache", "latest");
    let legacy_latest_alias_tag = legacy_scoped_ref_tag("my-cache", "latest");

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
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
                "blob_count": 0,
                "blob_total_size_bytes": 0,
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

    let latest_alias_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": latest_alias_tag
            }
        })))
        .expect(0)
        .create_async()
        .await;

    let latest_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&latest_alias_tag)
    );
    let latest_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&latest_alias_tag)
    );
    let latest_alias_pointer_mock = server
        .mock("GET", latest_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "4",
                "cache_entry_id": "entry-latest",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let latest_alias_confirm_mock = server
        .mock("PUT", latest_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "4")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let legacy_latest_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&legacy_latest_alias_tag)
    );
    let legacy_latest_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&legacy_latest_alias_tag)
    );
    let legacy_latest_alias_pointer_mock = server
        .mock("GET", legacy_latest_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "6",
                "cache_entry_id": "entry-latest-legacy",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let legacy_latest_alias_confirm_mock = server
        .mock("PUT", legacy_latest_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "6")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas",
            "write_scope_tag": "my-cache:latest"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v2/my-cache/manifests/{manifest_digest}"))
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    latest_alias_save_mock.assert_async().await;
    latest_alias_pointer_mock.assert_async().await;
    latest_alias_confirm_mock.assert_async().await;
    legacy_latest_alias_pointer_mock.assert_async().await;
    legacy_latest_alias_confirm_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_by_digest_rejects_mismatched_digest_reference() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri(
                "/v2/my-cache/manifests/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .body(Body::from(br#"{"schemaVersion":2}"#.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("\"DIGEST_INVALID\""));
}

#[tokio::test]
async fn test_manifest_put_rejects_invalid_json_body() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from("{not-json"))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("\"MANIFEST_INVALID\""));
}

#[tokio::test]
async fn test_manifest_put_rejects_missing_blob_with_blob_unknown_even_in_best_effort_mode() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.fail_on_cache_error = false;

    let missing_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": missing_digest,
            "size": 10
        },
        "layers": []
    })
    .to_string();

    let check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": missing_digest,
                "size_bytes": 10
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": missing_digest,
                    "exists": false
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .expect(0)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get("X-BoringCache-Degraded").is_none());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
    assert_eq!(parsed["errors"][0]["detail"]["digest"], missing_digest);

    check_mock.assert_async().await;
    save_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_rejects_missing_artifact_blob_with_blob_unknown() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let missing_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let manifest_body = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
        "artifactType": "application/vnd.example.sbom.v1",
        "blobs": [{
            "mediaType": "application/vnd.example.sbom.v1+json",
            "digest": missing_digest,
            "size": 10
        }]
    })
    .to_string();

    let check_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches/blobs/check")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "verify_storage": true,
            "blobs": [{
                "digest": missing_digest,
                "size_bytes": 10
            }]
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "results": [{
                    "digest": missing_digest,
                    "exists": false
                }]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .expect(0)
        .create_async()
        .await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .header(
                "Content-Type",
                "application/vnd.oci.artifact.manifest.v1+json",
            )
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
    assert_eq!(parsed["errors"][0]["detail"]["digest"], missing_digest);

    check_mock.assert_async().await;
    save_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_fails_on_alias_error_in_strict_mode() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.configured_human_tags = vec!["human-alias".to_string()];
    state.fail_on_cache_error = true;
    let capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "features": {
                    "tag_publish_v2": true,
                    "cas_publish_bootstrap_if_match": "0"
                }
            })
            .to_string(),
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = namespaced_scoped_ref_tag("human-alias", "my-cache", "main");
    let digest_alias_tag = digest_tag(&manifest_digest);

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
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
                "blob_count": 0,
                "blob_total_size_bytes": 0,
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

    let digest_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&digest_alias_tag)
    );
    let digest_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&digest_alias_tag)
    );
    let digest_alias_pointer_mock = server
        .mock("GET", digest_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
        .expect(1)
        .create_async()
        .await;
    let digest_alias_publish_error_mock = server
        .mock("PUT", digest_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "0")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas"
        })))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .expect_at_least(1)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    digest_alias_pointer_mock.assert_async().await;
    digest_alias_publish_error_mock.assert_async().await;
    capabilities_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_fails_required_human_alias_after_skipping_optional_alias_error() {
    let mut server = Server::new_async().await;
    let (mut state, _home, _guard) = setup(&server).await;
    state.configured_human_tags = vec!["human-alias".to_string()];
    state.fail_on_cache_error = false;
    let capabilities_mock = server
        .mock("GET", "/v2/capabilities")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "features": {
                    "tag_publish_v2": true,
                    "cas_publish_bootstrap_if_match": "0"
                }
            })
            .to_string(),
        )
        .expect_at_least(1)
        .create_async()
        .await;

    let manifest_body = br#"{"schemaVersion":2}"#.to_vec();
    let manifest_digest = cas_oci::prefixed_sha256_digest(&manifest_body);
    let primary_tag = namespaced_scoped_ref_tag("human-alias", "my-cache", "main");
    let digest_alias_tag = digest_tag(&manifest_digest);
    let legacy_alias_tag = legacy_scoped_ref_tag("my-cache", "main");

    let primary_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": primary_tag
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
                "blob_count": 0,
                "blob_total_size_bytes": 0,
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

    let digest_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&digest_alias_tag)
    );
    let digest_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&digest_alias_tag)
    );
    let digest_alias_pointer_mock = server
        .mock("GET", digest_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(404)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"Tag not found","current_version":"0"}"#)
        .expect(1)
        .create_async()
        .await;
    let digest_alias_publish_error_mock = server
        .mock("PUT", digest_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "0")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas"
        })))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .expect_at_least(1)
        .create_async()
        .await;

    let human_alias_tag = "human-alias";
    let human_alias_save_mock = server
        .mock("POST", "/v2/workspaces/org/repo/caches")
        .match_header("authorization", "Bearer test-token")
        .match_body(Matcher::PartialJson(json!({
            "cache": {
                "tag": human_alias_tag
            }
        })))
        .expect(0)
        .create_async()
        .await;
    let human_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(human_alias_tag)
    );
    let human_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(human_alias_tag)
    );
    let human_alias_pointer_mock = server
        .mock("GET", human_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "5",
                "cache_entry_id": "entry-human-alias",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let human_alias_confirm_mock = server
        .mock("PUT", human_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "5")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas"
        })))
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"backend unavailable"}"#)
        .expect_at_least(1)
        .create_async()
        .await;
    let legacy_alias_publish_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/publish",
        urlencoding::encode(&legacy_alias_tag)
    );
    let legacy_alias_pointer_path = format!(
        "/v2/workspaces/org/repo/caches/tags/{}/pointer",
        urlencoding::encode(&legacy_alias_tag)
    );
    let legacy_alias_pointer_mock = server
        .mock("GET", legacy_alias_pointer_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "7",
                "cache_entry_id": "entry-legacy-alias",
                "status": "ready"
            })
            .to_string(),
        )
        .expect(0)
        .create_async()
        .await;
    let legacy_alias_confirm_mock = server
        .mock("PUT", legacy_alias_publish_path.as_str())
        .match_header("authorization", "Bearer test-token")
        .match_header("if-match", "7")
        .match_body(Matcher::PartialJson(json!({
            "cache_entry_id": "entry-primary",
            "publish_mode": "cas",
            "write_scope_tag": "my-cache:main"
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "version": "8",
                "status": "ok",
                "cache_entry_id": "entry-primary"
            })
            .to_string(),
        )
        .expect(0)
        .create_async()
        .await;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "INTERNAL_ERROR");

    primary_save_mock.assert_async().await;
    pointer_upload_mock.assert_async().await;
    primary_pointer_mock.assert_async().await;
    primary_confirm_mock.assert_async().await;
    digest_alias_pointer_mock.assert_async().await;
    digest_alias_publish_error_mock.assert_async().await;
    human_alias_save_mock.assert_async().await;
    human_alias_pointer_mock.assert_async().await;
    human_alias_confirm_mock.assert_async().await;
    legacy_alias_pointer_mock.assert_async().await;
    legacy_alias_confirm_mock.assert_async().await;
    capabilities_mock.assert_async().await;
}

#[tokio::test]
async fn test_manifest_put_rejects_invalid_blob_digest() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let manifest_body = br#"{
        "schemaVersion": 2,
        "config": {
            "digest": "sha256:not-a-valid-digest",
            "size": 123
        },
        "layers": []
    }"#;

    let app = build_router(state);
    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri("/v2/my-cache/manifests/main")
            .body(Body::from(manifest_body.to_vec()))
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
async fn test_oci_error_envelope_format() {
    use axum::response::IntoResponse;
    use boring_cache_cli::serve::error::OciError;
    let err = OciError::manifest_unknown("test detail");
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["errors"][0]["code"], "MANIFEST_UNKNOWN");
    assert_eq!(parsed["errors"][0]["message"], "test detail");
}

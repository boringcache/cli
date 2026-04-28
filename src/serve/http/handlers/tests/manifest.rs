use super::*;

#[test]
fn extract_blob_descriptors_includes_child_manifests_for_index() {
    let index_json = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 500, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
            {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size": 600, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        ]
    });
    let blobs = extract_blob_descriptors(&index_json).unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(
        blobs[0].digest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        blobs[1].digest,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

#[test]
fn extract_blob_descriptors_includes_config_and_layers() {
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "config": {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 100},
        "layers": [
            {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size": 2000},
            {"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "size": 3000}
        ]
    });
    let blobs = extract_blob_descriptors(&manifest_json).unwrap();
    assert_eq!(blobs.len(), 3);
    assert_eq!(
        blobs[0].digest,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        blobs[1].digest,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        blobs[2].digest,
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
}

#[test]
fn extract_blob_descriptors_dedupes_by_digest() {
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "config": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
        "layers": [
            {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
            {"digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "size": 3000}
        ]
    });

    let blobs = extract_blob_descriptors(&manifest_json).unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(
        blobs[0].digest,
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    );
    assert_eq!(
        blobs[1].digest,
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    );
}

#[test]
fn extract_blob_descriptors_rejects_conflicting_sizes_for_same_digest() {
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "config": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 32},
        "layers": [
            {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 64}
        ]
    });

    let error = extract_blob_descriptors(&manifest_json).unwrap_err();
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn extract_blob_descriptors_rejects_invalid_digest_format() {
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "config": {"digest": "sha256:not-a-real-digest", "size": 32},
        "layers": []
    });

    let error = extract_blob_descriptors(&manifest_json).unwrap_err();
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn detect_manifest_content_type_prefers_declared_media_type() {
    let docker_manifest = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 32
            },
            "layers": []
        }"#;

    assert_eq!(
        detect_manifest_content_type_for_tests(docker_manifest),
        "application/vnd.docker.distribution.manifest.v2+json"
    );
}

#[test]
fn resolve_pushed_manifest_content_type_prefers_header_when_body_omits_media_type() {
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "manifests": []
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/vnd.docker.distribution.manifest.list.v2+json"
            .parse()
            .unwrap(),
    );

    assert_eq!(
        resolve_pushed_manifest_content_type_for_tests(&headers, &manifest_json).unwrap(),
        "application/vnd.docker.distribution.manifest.list.v2+json"
    );
}

#[test]
fn resolve_pushed_manifest_content_type_rejects_header_media_type_mismatch() {
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": []
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/vnd.docker.distribution.manifest.list.v2+json"
            .parse()
            .unwrap(),
    );

    let error =
        resolve_pushed_manifest_content_type_for_tests(&headers, &manifest_json).unwrap_err();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert!(
        error
            .message()
            .contains("does not match declared mediaType")
    );
}

#[tokio::test]
async fn expand_manifest_blob_descriptors_skips_non_manifest_entries_in_manifests_array() {
    let state = test_state();
    let layer_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cache_config_digest =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let manifest_list = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "digest": layer_digest,
                "size": 128,
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
            },
            {
                "digest": cache_config_digest,
                "size": 64,
                "mediaType": "application/vnd.buildkit.cacheconfig.v0"
            }
        ]
    });

    let blobs = expand_manifest_blob_descriptors(&state, "cache", &manifest_list)
        .await
        .expect("expand top-level descriptors without recursing into non-manifests");
    let digests: Vec<&str> = blobs.iter().map(|blob| blob.digest.as_str()).collect();

    assert_eq!(blobs.len(), 2);
    assert!(digests.contains(&layer_digest));
    assert!(digests.contains(&cache_config_digest));
}

#[tokio::test]
async fn stage_manifest_reference_uploads_ignores_non_manifest_entries() {
    let state = test_state();
    let layer_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cache_config_digest =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let manifest_list = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "digest": layer_digest,
                "size": 128,
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
            },
            {
                "digest": cache_config_digest,
                "size": 64,
                "mediaType": "application/vnd.buildkit.cacheconfig.v0"
            }
        ]
    });

    let blob_descriptors = extract_blob_descriptors(&manifest_list).unwrap();
    stage_manifest_reference_uploads(&state, "cache", &blob_descriptors, &manifest_list)
        .await
        .expect("ignore non-manifest top-level descriptors");

    let sessions = state.upload_sessions.read().await;
    assert!(
        sessions.find_by_digest(layer_digest).is_none(),
        "layer descriptor should not be staged as a manifest upload"
    );
    assert!(
        sessions.find_by_digest(cache_config_digest).is_none(),
        "cache config descriptor should not be staged as a manifest upload"
    );
}

#[tokio::test]
async fn expand_manifest_blob_descriptors_includes_child_manifest_descendants() {
    let state = test_state();
    let child_config_digest =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let child_layer_digest =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let child_manifest = format!(
        r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{"digest": "{child_config_digest}", "size": 12}},
                "layers": [
                    {{"digest": "{child_layer_digest}", "size": 34}}
                ]
            }}"#
    );
    let child_digest = cas_oci::prefixed_sha256_digest(child_manifest.as_bytes());
    let child_size = child_manifest.len() as u64;
    let child_tag = digest_tag(&child_digest);
    state.oci_manifest_cache.insert(
        child_tag,
        Arc::new(OciManifestCacheEntry {
            index_json: child_manifest.into_bytes(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest_digest: child_digest.clone(),
            cache_entry_id: "entry-child".to_string(),
            blobs: vec![],
            name: "cache".to_string(),
            inserted_at: Instant::now(),
        }),
    );

    let index_json = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {
                "digest": child_digest,
                "size": child_size,
                "mediaType": "application/vnd.oci.image.manifest.v1+json"
            }
        ]
    });

    let blobs = expand_manifest_blob_descriptors(&state, "cache", &index_json)
        .await
        .expect("expand child descriptors");
    let digests: Vec<&str> = blobs.iter().map(|blob| blob.digest.as_str()).collect();

    assert_eq!(blobs.len(), 3);
    assert!(digests.contains(&child_digest.as_str()));
    assert!(digests.contains(&child_config_digest));
    assert!(digests.contains(&child_layer_digest));
}

#[tokio::test]
async fn stage_manifest_reference_uploads_seeds_child_manifest_sessions() {
    let state = test_state();
    let child_manifest = br#"{"schemaVersion":2,"config":{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":12},"layers":[]}"#;
    let child_digest = cas_oci::prefixed_sha256_digest(child_manifest);
    let child_size = child_manifest.len() as u64;
    let child_tag = digest_tag(&child_digest);
    state.oci_manifest_cache.insert(
        child_tag,
        Arc::new(OciManifestCacheEntry {
            index_json: child_manifest.to_vec(),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            manifest_digest: child_digest.clone(),
            cache_entry_id: "entry-1".to_string(),
            blobs: vec![],
            name: "cache".to_string(),
            inserted_at: Instant::now(),
        }),
    );

    let index_json = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {"digest": child_digest, "size": child_size, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        ]
    });
    let blob_descriptors = extract_blob_descriptors(&index_json).unwrap();
    stage_manifest_reference_uploads(&state, "cache", &blob_descriptors, &index_json)
        .await
        .expect("stage child manifest");

    let sessions = state.upload_sessions.read().await;
    let session = sessions
        .find_by_name_and_digest("cache", &blob_descriptors[0].digest)
        .expect("staged upload session");
    assert_eq!(session.finalized_size, Some(child_size));
    assert_eq!(
        session.finalized_digest.as_deref(),
        Some(blob_descriptors[0].digest.as_str())
    );
}

#[test]
fn adaptive_blob_upload_concurrency_is_bounded() {
    assert_eq!(adaptive_blob_upload_concurrency(1), 1);

    let medium = adaptive_blob_upload_concurrency(5);
    assert!((1..=5).contains(&medium));

    let larger = adaptive_blob_upload_concurrency(32);
    assert!((1..=32).contains(&larger));
}

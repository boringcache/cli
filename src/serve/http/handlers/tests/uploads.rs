use super::*;

#[tokio::test]
async fn put_upload_allows_local_reuse_when_finalize_payload_is_empty() {
    let state = test_state();
    let digest = cas_oci::prefixed_sha256_digest(b"existing payload");
    let filled_path = write_temp_upload_file(b"existing payload").await;
    let empty_path = write_temp_upload_file(&[]).await;

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "filled-session".to_string(),
            name: "cache".to_string(),
            temp_path: filled_path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: 16,
            finalized_digest: Some(digest.clone()),
            finalized_size: Some(16),
            created_at: Instant::now(),
        });
        sessions.create(UploadSession {
            id: "empty-session".to_string(),
            name: "cache".to_string(),
            temp_path: empty_path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: 0,
            finalized_digest: None,
            finalized_size: None,
            created_at: Instant::now(),
        });
    }

    let mut params = HashMap::new();
    params.insert("digest".to_string(), digest.clone());
    let response = put_upload(
        state.clone(),
        "cache".to_string(),
        "empty-session".to_string(),
        params,
        HeaderMap::new(),
        Body::empty(),
    )
    .await
    .expect("put upload should succeed via local reuse");

    assert_eq!(response.status(), StatusCode::CREATED);
    let sessions = state.upload_sessions.read().await;
    let empty = sessions.get("empty-session").expect("empty session");
    assert_eq!(empty.finalized_digest.as_deref(), Some(digest.as_str()));

    let _ = tokio::fs::remove_file(&filled_path).await;
    let _ = tokio::fs::remove_file(&empty_path).await;
}

#[tokio::test]
async fn start_upload_mount_returns_created_for_existing_local_digest() {
    let state = test_state();
    let digest = cas_oci::prefixed_sha256_digest(b"mount-existing");
    let filled_path = write_temp_upload_file(b"mount-existing").await;

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "filled-session".to_string(),
            name: "cache".to_string(),
            temp_path: filled_path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: 14,
            finalized_digest: Some(digest.clone()),
            finalized_size: Some(14),
            created_at: Instant::now(),
        });
    }

    let mut params = HashMap::new();
    params.insert("mount".to_string(), digest.clone());
    params.insert("from".to_string(), "cache".to_string());

    let response = start_upload(state, "cache".to_string(), params, Body::empty())
        .await
        .expect("start upload mount should reuse local blob");
    assert_eq!(response.status(), StatusCode::CREATED);

    let _ = tokio::fs::remove_file(&filled_path).await;
}

#[tokio::test]
async fn blob_head_uses_prefetched_local_blob_without_locator_entry() {
    let state = test_state();
    let payload = b"prefetched-oci-blob";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("insert prefetched blob");

    let response = get_blob(
        Method::HEAD,
        HeaderMap::new(),
        state,
        "cache".to_string(),
        digest.clone(),
    )
    .await
    .expect("head should use prefetched local blob");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|value| value.to_str().ok()),
        Some(digest.as_str())
    );
    assert_eq!(
        response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        Some(payload.len().to_string())
    );
}

#[tokio::test]
async fn blob_get_uses_zero_byte_local_upload_session_without_locator_entry() {
    let state = test_state();
    let digest = cas_oci::prefixed_sha256_digest(b"");
    let path = write_temp_upload_file(&[]).await;

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession::owned_temp_file(
            "upload-zero-byte".to_string(),
            "cache".to_string(),
            path,
            0,
            Some(digest.clone()),
            Some(0),
        ));
    }

    let response = get_blob(
        Method::GET,
        HeaderMap::new(),
        state,
        "cache".to_string(),
        digest.clone(),
    )
    .await
    .expect("zero-byte local upload should be served locally");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|value| value.to_str().ok()),
        Some(digest.as_str())
    );
    assert_eq!(
        response
            .headers()
            .get("Content-Length")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("collect zero-byte body");
    assert!(body.is_empty());
}

#[tokio::test]
async fn start_upload_mount_reuses_prefetched_local_blob() {
    let state = test_state();
    let payload = b"prefetched-mount";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("insert prefetched blob");

    let mut params = HashMap::new();
    params.insert("mount".to_string(), digest.clone());
    params.insert("from".to_string(), "cache".to_string());

    let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
        .await
        .expect("start upload mount should reuse prefetched blob");

    assert_eq!(response.status(), StatusCode::CREATED);

    let sessions = state.upload_sessions.read().await;
    let mounted = sessions
        .find_by_name_and_digest("cache", &digest)
        .expect("mount should create publish session");
    assert_eq!(mounted.finalized_size, Some(payload.len() as u64));
    assert_eq!(read_upload_session_body(mounted).await, payload);
    assert!(!mounted.owns_temp_file());
}

#[tokio::test]
async fn start_upload_mount_reuses_zero_byte_local_upload_session() {
    let state = test_state();
    let digest = cas_oci::prefixed_sha256_digest(b"");
    let path = write_temp_upload_file(&[]).await;

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession::owned_temp_file(
            "upload-zero-byte-source".to_string(),
            "other-cache".to_string(),
            path,
            0,
            Some(digest.clone()),
            Some(0),
        ));
    }

    let mut params = HashMap::new();
    params.insert("mount".to_string(), digest.clone());
    params.insert("from".to_string(), "cache".to_string());

    let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
        .await
        .expect("start upload mount should reuse zero-byte local blob");

    assert_eq!(response.status(), StatusCode::CREATED);

    let sessions = state.upload_sessions.read().await;
    let mounted = sessions
        .find_by_name_and_digest("cache", &digest)
        .expect("mount should create zero-byte publish session");
    assert_eq!(mounted.finalized_size, Some(0));
    assert_eq!(read_upload_session_body(mounted).await, b"");
}

#[tokio::test]
async fn delete_upload_releases_borrowed_session_without_deleting_cache_body() {
    let state = test_state();
    let payload = b"borrowed-delete";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("insert prefetched blob");

    let mut params = HashMap::new();
    params.insert("mount".to_string(), digest.clone());
    params.insert("from".to_string(), "cache".to_string());
    let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
        .await
        .expect("start upload mount should reuse prefetched blob");
    assert_eq!(response.status(), StatusCode::CREATED);

    let (session_id, body_path) = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .find_by_name_and_digest("cache", &digest)
            .expect("borrowed session");
        assert!(!session.owns_temp_file());
        (session.id.clone(), session.body_path().to_path_buf())
    };

    let response = delete_upload(state.clone(), session_id.clone())
        .await
        .expect("delete borrowed session");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let sessions = state.upload_sessions.read().await;
    assert!(sessions.get(&session_id).is_none());
    drop(sessions);
    assert!(tokio::fs::metadata(&body_path).await.is_ok());
    assert!(state.blob_read_cache.get_handle(&digest).await.is_some());
}

#[tokio::test]
async fn published_owned_upload_session_is_promoted_to_body_cache() {
    let state = test_state();
    let payload = b"published-upload-body";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    let temp_path = write_temp_upload_file(payload).await;
    let session_id = "upload-session-promote".to_string();

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession::owned_temp_file(
            session_id.clone(),
            "cache".to_string(),
            temp_path,
            payload.len() as u64,
            Some(digest.clone()),
            Some(payload.len() as u64),
        ));
    }

    crate::serve::engines::oci::publish::cleanup_present_blob_sessions(
        &state,
        &[PresentBlob {
            digest: digest.clone(),
            size_bytes: payload.len() as u64,
            source: PresentBlobSource::UploadSession,
            upload_session_id: Some(session_id.clone()),
        }],
    )
    .await;

    let sessions = state.upload_sessions.read().await;
    assert!(sessions.get(&session_id).is_none());
    drop(sessions);

    let handle = state
        .blob_read_cache
        .get_handle(&digest)
        .await
        .expect("published body should be promoted to read cache");
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(handle.path())
        .await
        .expect("open promoted body");
    if handle.offset() > 0 {
        file.seek(std::io::SeekFrom::Start(handle.offset()))
            .await
            .expect("seek promoted body");
    }
    let mut restored = vec![0; handle.size_bytes() as usize];
    file.read_exact(&mut restored)
        .await
        .expect("read promoted body");
    assert_eq!(restored, payload);
}

#[tokio::test]
async fn manifest_availability_stages_local_body_cache_for_publish() {
    let state = test_state();
    let payload = b"local-body-cache-publish";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("insert local body cache blob");

    let present = ensure_manifest_blobs_present(
        &state,
        "cache",
        &[BlobDescriptor {
            digest: digest.clone(),
            size_bytes: payload.len() as u64,
        }],
    )
    .await
    .expect("local body cache should prove descriptor availability");

    assert_eq!(present.len(), 1);
    assert_eq!(present[0].source, PresentBlobSource::LocalBodyCache);

    let staged_body = {
        let sessions = state.upload_sessions.read().await;
        let session = sessions
            .find_by_name_and_digest("cache", &digest)
            .expect("local body cache should be staged as upload session");
        assert!(!session.owns_temp_file());
        read_upload_session_body(session).await
    };
    assert_eq!(staged_body, payload);
}

#[tokio::test]
async fn manifest_availability_rejects_local_body_cache_size_mismatch() {
    let state = test_state();
    let payload = b"wrong-size-local-body-cache";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("insert local body cache blob");

    let error = ensure_manifest_blobs_present(
        &state,
        "cache",
        &[BlobDescriptor {
            digest: digest.clone(),
            size_bytes: payload.len() as u64 + 1,
        }],
    )
    .await
    .expect_err("descriptor size mismatch should fail");

    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert!(error.message().contains("descriptor size mismatch"));
}

#[tokio::test]
async fn start_upload_mount_from_existing_session_stages_target_session() {
    let state = test_state();
    let payload = b"source-repo-mount";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    let source_path = write_temp_upload_file(payload).await;

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "source-session".to_string(),
            name: "source".to_string(),
            temp_path: source_path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: payload.len() as u64,
            finalized_digest: Some(digest.clone()),
            finalized_size: Some(payload.len() as u64),
            created_at: Instant::now(),
        });
    }

    let mut params = HashMap::new();
    params.insert("mount".to_string(), digest.clone());
    params.insert("from".to_string(), "source".to_string());

    let response = start_upload(state.clone(), "cache".to_string(), params, Body::empty())
        .await
        .expect("start upload mount should stage target session");

    assert_eq!(response.status(), StatusCode::CREATED);

    let target_path = {
        let sessions = state.upload_sessions.read().await;
        let mounted = sessions
            .find_by_name_and_digest("cache", &digest)
            .expect("mount should stage target session");
        assert_eq!(mounted.finalized_size, Some(payload.len() as u64));
        mounted.temp_path.clone()
    };
    assert_eq!(
        tokio::fs::read(&target_path).await.expect("mounted copy"),
        payload
    );

    let _ = tokio::fs::remove_file(&source_path).await;
    let _ = tokio::fs::remove_file(&target_path).await;
}

#[tokio::test]
async fn concurrent_start_upload_mounts_stage_one_target_session() {
    let state = test_state();
    let payload = b"prefetched-concurrent-mount";
    let digest = cas_oci::prefixed_sha256_digest(payload);
    state
        .blob_read_cache
        .insert(&digest, payload)
        .await
        .expect("insert prefetched blob");

    let mut tasks = Vec::new();
    for _ in 0..12 {
        let state = state.clone();
        let digest = digest.clone();
        tasks.push(tokio::spawn(async move {
            let mut params = HashMap::new();
            params.insert("mount".to_string(), digest);
            params.insert("from".to_string(), "source".to_string());
            start_upload(state, "cache".to_string(), params, Body::empty()).await
        }));
    }

    for task in tasks {
        let response = task
            .await
            .expect("mount task should complete")
            .expect("mount request should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let staged_body = {
        let sessions = state.upload_sessions.read().await;
        let mounted = sessions
            .find_by_name_and_digest("cache", &digest)
            .expect("mount should stage target session");
        assert_eq!(mounted.finalized_size, Some(payload.len() as u64));
        assert!(!mounted.owns_temp_file());
        read_upload_session_body(mounted).await
    };
    assert_eq!(staged_body, payload);
}

#[tokio::test]
async fn put_upload_retries_local_reuse_before_remote_lookup() {
    let state = test_state();
    let digest = cas_oci::prefixed_sha256_digest(b"delayed payload");
    let delayed_path = write_temp_upload_file(b"delayed payload").await;
    let empty_path = write_temp_upload_file(&[]).await;

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "delayed-session".to_string(),
            name: "cache".to_string(),
            temp_path: delayed_path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: 0,
            finalized_digest: None,
            finalized_size: None,
            created_at: Instant::now(),
        });
        sessions.create(UploadSession {
            id: "empty-session".to_string(),
            name: "cache".to_string(),
            temp_path: empty_path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: 0,
            finalized_digest: None,
            finalized_size: None,
            created_at: Instant::now(),
        });
    }

    let state_for_finalize = state.clone();
    let digest_for_finalize = digest.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        let mut sessions = state_for_finalize.upload_sessions.write().await;
        let session = sessions
            .get_mut("delayed-session")
            .expect("delayed session exists");
        session.bytes_received = 15;
        session.finalized_size = Some(15);
        session.finalized_digest = Some(digest_for_finalize);
    });

    let mut params = HashMap::new();
    params.insert("digest".to_string(), digest.clone());
    let response = put_upload(
        state,
        "cache".to_string(),
        "empty-session".to_string(),
        params,
        HeaderMap::new(),
        Body::empty(),
    )
    .await
    .expect("empty finalize should reuse delayed local digest");

    assert_eq!(response.status(), StatusCode::CREATED);

    let _ = tokio::fs::remove_file(&delayed_path).await;
    let _ = tokio::fs::remove_file(&empty_path).await;
}

#[tokio::test]
async fn put_upload_returns_internal_error_on_body_stream_error() {
    let state = test_state();
    let path = write_temp_upload_file(&[]).await;
    let digest = cas_oci::prefixed_sha256_digest(b"payload");

    {
        let mut sessions = state.upload_sessions.write().await;
        sessions.create(UploadSession {
            id: "stream-error-session".to_string(),
            name: "cache".to_string(),
            temp_path: path.clone(),
            body: UploadSessionBody::OwnedTempFile,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            bytes_received: 0,
            finalized_digest: None,
            finalized_size: None,
            created_at: Instant::now(),
        });
    }

    let mut params = HashMap::new();
    params.insert("digest".to_string(), digest);

    let body = Body::from_stream(futures_util::stream::once(async {
        let error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        Err::<Bytes, std::io::Error>(error)
    }));

    let error = put_upload(
        state,
        "cache".to_string(),
        "stream-error-session".to_string(),
        params,
        HeaderMap::new(),
        body,
    )
    .await
    .expect_err("stream error should fail finalize");

    assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(error.message().contains("body stream error"));

    let _ = tokio::fs::remove_file(&path).await;
}

#[test]
fn parse_upload_offset_prefers_range_start() {
    let mut headers = HeaderMap::new();
    headers.insert("Range", "0-1023".parse().unwrap());
    assert_eq!(parse_upload_offset(&headers), Some(0));
}

#[test]
fn parse_put_upload_offset_uses_content_range_start() {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Range", "bytes 4096-8191".parse().unwrap());
    assert_eq!(parse_put_upload_offset(&headers, 4096), Ok(Some(4096)));
}

#[test]
fn parse_put_upload_offset_uses_range_end_for_finalize() {
    let mut headers = HeaderMap::new();
    headers.insert("Range", "0-8191".parse().unwrap());
    assert_eq!(parse_put_upload_offset(&headers, 8192), Ok(Some(8192)));
}

#[test]
fn parse_put_upload_offset_clamps_empty_range_to_current_size() {
    let mut headers = HeaderMap::new();
    headers.insert("Range", "0-0".parse().unwrap());
    assert_eq!(parse_put_upload_offset(&headers, 1), Ok(Some(1)));
}

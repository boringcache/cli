use super::*;

pub(crate) enum FlushResult {
    Ok,
    Conflict,
    Error,
    Permanent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushMode {
    Normal,
    Shutdown,
}

impl FlushMode {
    pub(crate) fn publishes_stable_manifest(self) -> bool {
        matches!(self, FlushMode::Shutdown)
    }
}

pub(crate) async fn flush_kv_index(state: &AppState) -> FlushResult {
    flush_kv_index_with_mode(state, FlushMode::Normal).await
}

pub(crate) async fn flush_kv_index_on_shutdown(state: &AppState) -> FlushResult {
    flush_kv_index_with_mode(state, FlushMode::Shutdown).await
}

pub(crate) async fn flush_kv_index_with_mode(
    state: &AppState,
    flush_mode: FlushMode,
) -> FlushResult {
    let guard = state.kv_flush_lock.lock().await;

    let (pending_entries, pending_blob_paths) = {
        let mut pending = state.kv_pending.write().await;
        if pending.is_empty() {
            return FlushResult::Ok;
        }
        pending.take_all()
    };

    if pending_entries.is_empty() {
        return FlushResult::Ok;
    }

    {
        let mut flushing = state.kv_flushing.write().await;
        *flushing = Some(KvFlushingSnapshot::new(
            pending_entries.clone(),
            pending_blob_paths
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ));
    }

    let entry_count = pending_entries.len();

    let result = match do_flush(state, &pending_entries, &pending_blob_paths, flush_mode).await {
        Ok((merged_entries, merged_blob_order, cache_entry_id, stable_publish)) => {
            let promoted =
                promote_pending_blobs_to_read_cache(state, &pending_entries, &pending_blob_paths)
                    .await;
            {
                let mut published = state.kv_published_index.write().await;
                published.update(
                    merged_entries.into_iter().collect(),
                    merged_blob_order,
                    cache_entry_id.clone(),
                    stable_publish,
                );
            }
            {
                let mut flushing = state.kv_flushing.write().await;
                *flushing = None;
            }
            clear_tag_misses(state, &state.primary_cache_tag);

            cleanup_blob_files(&pending_blob_paths).await;
            state.kv_last_put.store(0, Ordering::Release);

            if crate::serve::state::diagnostics_enabled() {
                eprintln!(
                    "KV batch: flushed {entry_count} new entries ({} blobs cleaned up, {promoted} promoted to read cache)",
                    pending_blob_paths.len(),
                );
            }
            drop(guard);
            if stable_publish {
                preload_download_urls(state, &cache_entry_id).await;
            }
            FlushResult::Ok
        }
        Err(FlushError::Conflict(msg)) => {
            eprintln!("KV batch flush: skipped — tag conflict ({msg})");
            let mut pending = state.kv_pending.write().await;
            let paths_to_cleanup = pending.restore(pending_entries, pending_blob_paths);
            drop(pending);
            cleanup_paths(paths_to_cleanup).await;
            let (base_ms, jitter_ms) = conflict_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Conflict
        }
        Err(FlushError::Transient(msg)) => {
            eprintln!("KV batch flush failed: {msg}");
            let mut pending = state.kv_pending.write().await;
            let paths_to_cleanup = pending.restore(pending_entries, pending_blob_paths);
            drop(pending);
            cleanup_paths(paths_to_cleanup).await;
            let (base_ms, jitter_ms) = transient_backoff_window(&msg);
            set_next_flush_at_with_jitter(state, base_ms, jitter_ms).await;
            FlushResult::Error
        }
        Err(FlushError::Permanent(msg)) => {
            if state.fail_on_cache_error {
                eprintln!(
                    "KV batch flush failed permanently; restored pending batch for strict shutdown retry: {msg}"
                );
                let mut pending = state.kv_pending.write().await;
                let paths_to_cleanup = pending.restore(pending_entries, pending_blob_paths);
                drop(pending);
                cleanup_paths(paths_to_cleanup).await;
            } else {
                eprintln!("KV batch flush dropped permanently: {msg}");
                cleanup_blob_files(&pending_blob_paths).await;
                state.kv_last_put.store(0, Ordering::Release);
            }
            FlushResult::Permanent
        }
    };

    if should_clear_flushing_after_flush(&result) {
        let mut flushing = state.kv_flushing.write().await;
        *flushing = None;
    }

    result
}

pub(crate) fn should_clear_flushing_after_flush(result: &FlushResult) -> bool {
    !matches!(result, FlushResult::Ok)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KvFlushPublishPlan {
    pub(crate) tag: String,
    pub(crate) write_scope_tag: Option<String>,
    pub(crate) stable: bool,
}

pub(crate) async fn kv_flush_publish_plan(
    state: &AppState,
    flush_mode: FlushMode,
) -> KvFlushPublishPlan {
    let write_scope_tag = kv_primary_write_scope_tag(state);

    KvFlushPublishPlan {
        tag: kv_publish_cache_tag(state, write_scope_tag.as_deref()).await,
        write_scope_tag,
        stable: flush_mode.publishes_stable_manifest(),
    }
}

async fn kv_publish_cache_tag(state: &AppState, primary_write_scope_tag: Option<&str>) -> String {
    primary_write_scope_tag
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| state.primary_cache_tag.trim().to_string())
}

pub(crate) async fn do_flush(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
    flush_mode: FlushMode,
) -> Result<
    (
        BTreeMap<String, BlobDescriptor>,
        Vec<BlobDescriptor>,
        String,
        bool,
    ),
    FlushError,
> {
    let flush_started_at = std::time::Instant::now();
    let diagnostics = crate::serve::state::diagnostics_enabled();
    let publish_plan = kv_flush_publish_plan(state, flush_mode).await;

    let (published_snapshot, published_blob_order, published_cache_entry_id) = {
        let published = state.kv_published_index.read().await;
        (
            published.entries_snapshot(),
            published.unique_blobs(),
            published.cache_entry_id().map(str::to_string),
        )
    };

    let (backend_entries, backend_blob_order) =
        match load_existing_index_snapshot(state, false).await {
            Ok((existing, blob_order, _, _)) => (existing, blob_order),
            Err(e) => {
                log::warn!("KV flush: failed to load existing index: {e:?}");
                (BTreeMap::new(), Vec::new())
            }
        };
    let (mut entries, base_selection) =
        select_flush_base_entries(backend_entries, published_snapshot.as_ref());
    let base_blob_order = match base_selection {
        FlushBaseSelection::Backend => backend_blob_order,
        FlushBaseSelection::PublishedFallback { .. } => published_blob_order,
    };
    let existing_count = entries.len();
    let (
        filtered_pending_entries,
        filtered_pending_blob_paths,
        missing_pending_digests,
        missing_pending_entries,
    ) = filter_pending_entries_with_local_blobs(pending_entries, pending_blob_paths);
    if let FlushBaseSelection::PublishedFallback {
        backend_entry_count,
        published_entry_count,
        missing_published_keys,
        mismatched_published_keys,
    } = base_selection
        && diagnostics
    {
        if backend_entry_count == 0 {
            eprintln!(
                "KV flush: backend index empty, using published snapshot with {published_entry_count} entries"
            );
        } else {
            eprintln!(
                "KV flush: backend index stale (backend={backend_entry_count}, published={published_entry_count}, missing_keys={missing_published_keys}, mismatched_keys={mismatched_published_keys}); preserving in-memory snapshot"
            );
        }
    }
    if missing_pending_entries > 0 {
        eprintln!(
            "KV flush: dropped {missing_pending_entries} pending entries with missing local blobs ({} digests)",
            missing_pending_digests.len()
        );
    }
    entries.extend(
        filtered_pending_entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    let merged_blob_order = merge_blob_order(&entries, &base_blob_order);
    let total_count = entries.len();
    if diagnostics {
        eprintln!(
            "KV flush: merging {existing_count} existing + {} pending = {total_count} total entries",
            filtered_pending_entries.len()
        );
    }

    if !publish_plan.stable {
        let checkpoint_cache_entry_id = checkpoint_kv_blobs(
            state,
            &filtered_pending_entries,
            &filtered_pending_blob_paths,
            diagnostics,
            flush_started_at,
        )
        .await?;
        return Ok((
            entries,
            merged_blob_order,
            published_cache_entry_id.unwrap_or(checkpoint_cache_entry_id),
            false,
        ));
    }

    let cache_entry_id = publish_kv_manifest(
        state,
        &entries,
        &merged_blob_order,
        &filtered_pending_blob_paths,
        &publish_plan,
        diagnostics,
        flush_started_at,
    )
    .await?;

    Ok((entries, merged_blob_order, cache_entry_id, true))
}

#[allow(clippy::too_many_arguments)]
async fn publish_kv_manifest(
    state: &AppState,
    entries: &BTreeMap<String, BlobDescriptor>,
    merged_blob_order: &[BlobDescriptor],
    local_blob_paths: &HashMap<String, PathBuf>,
    publish_plan: &KvFlushPublishPlan,
    diagnostics: bool,
    flush_started_at: std::time::Instant,
) -> Result<String, FlushError> {
    let tag = publish_plan.tag.clone();
    let primary_write_scope_tag = publish_plan.write_scope_tag.clone();
    let total_count = entries.len();
    let (pointer_bytes, blobs) = build_index_pointer(entries, merged_blob_order)
        .map_err(|e| FlushError::Transient(format!("build pointer failed: {e:?}")))?;

    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = blobs.len() as u64;
    let blob_total_size_bytes: u64 = blobs.iter().map(|b| b.size_bytes).sum();
    let file_count = entries.len().min(u32::MAX as usize) as u32;

    let request = kv_save_request(
        state,
        tag.clone(),
        primary_write_scope_tag.clone(),
        manifest_root_digest.clone(),
        expected_manifest_size,
        blob_count,
        blob_total_size_bytes,
        file_count,
    );

    let save_response = save_kv_entry(state, &request).await?;
    let confirm_cache_entry_id = save_response.cache_entry_id.clone();
    let confirm_manifest_digest = manifest_root_digest.clone();
    let confirm_tag = tag.clone();
    let confirm_write_scope_tag = primary_write_scope_tag.clone();

    if let Some(reason) = save_response.blocking_pending_cas_reason(&manifest_root_digest) {
        return Err(FlushError::Conflict(format!(
            "save_entry failed: another cache upload is in progress ({reason})"
        )));
    }

    if save_response.should_skip_existing_uploads_for(&manifest_root_digest) {
        let reconcile_blobs = local_reconcile_blobs(entries, local_blob_paths);
        if !reconcile_blobs.is_empty() {
            match upload_blobs(
                state,
                &save_response.cache_entry_id,
                &reconcile_blobs,
                local_blob_paths,
            )
            .await
            {
                Ok(heal_stats) => {
                    if let Err(error) = try_commit_blob_receipts(
                        &state.api_client,
                        &state.workspace,
                        save_response.upload_session_id.as_deref(),
                        heal_stats.uploaded_receipts.clone(),
                    )
                    .await
                    {
                        log::warn!(
                            "KV flush: exists=true blob reconcile receipt commit failed: {error:#}"
                        );
                    }
                    if heal_stats.missing_local_count > 0
                        || (diagnostics && heal_stats.uploaded_count > 0)
                    {
                        eprintln!(
                            "KV flush: exists=true blob reconcile uploaded={} already_present={} missing_local={}",
                            heal_stats.uploaded_count,
                            heal_stats.already_present_count,
                            heal_stats.missing_local_count
                        );
                    }
                }
                Err(error) => {
                    if let Some(partial_stats) = partial_blob_upload_stats(&error) {
                        if let Err(commit_error) = try_commit_blob_receipts(
                            &state.api_client,
                            &state.workspace,
                            save_response.upload_session_id.as_deref(),
                            partial_stats.uploaded_receipts.clone(),
                        )
                        .await
                        {
                            log::warn!(
                                "KV flush: exists=true partial blob receipt commit failed: {commit_error:#}"
                            );
                        }
                        if partial_stats.uploaded_count > 0 || partial_stats.missing_local_count > 0
                        {
                            eprintln!(
                                "KV flush: exists=true preserved partial blob uploads uploaded={} already_present={} missing_local={}",
                                partial_stats.uploaded_count,
                                partial_stats.already_present_count,
                                partial_stats.missing_local_count
                            );
                        }
                    }
                    log::warn!("KV flush: exists=true blob reconcile failed: {error}");
                }
            }
        }

        let confirm_request = ConfirmRequest {
            manifest_digest: confirm_manifest_digest.clone(),
            manifest_size: expected_manifest_size,
            manifest_etag: None,
            archive_size: None,
            archive_etag: None,
            blob_count: Some(blob_count),
            blob_total_size_bytes: Some(blob_total_size_bytes),
            file_count: Some(file_count),
            uncompressed_size: None,
            compressed_size: None,
            storage_mode: Some("cas".to_string()),
            tag: Some(confirm_tag.clone()),
            write_scope_tag: confirm_write_scope_tag.clone(),
        };
        let confirm_outcome =
            confirm_kv_flush(state, &confirm_cache_entry_id, &confirm_request).await?;
        let alias_count = if publish_plan.stable {
            bind_kv_alias_tags(state, &confirm_outcome.cache_entry_id, Some(&tag)).await?
        } else {
            0
        };
        if diagnostics {
            eprintln!(
                "KV flush publish: tag={} cache_entry_id={} state=stable alias_tags={}",
                tag, confirm_outcome.cache_entry_id, alias_count
            );
        }
        if diagnostics && alias_count > 0 {
            eprintln!(
                "KV alias publish completed: cache_entry_id={} alias_tags={}",
                confirm_outcome.cache_entry_id, alias_count
            );
        }

        if diagnostics {
            eprintln!(
                "KV flush: save_entry returned exists=true ({total_count} entries, {blob_count} blobs, digest={manifest_root_digest})"
            );
        }
        return Ok(confirm_outcome.cache_entry_id);
    }
    if diagnostics {
        eprintln!(
            "KV flush: uploading {total_count} entries, {blob_count} blobs, pointer={expected_manifest_size} bytes"
        );
    }

    let upload_stats_holder = Arc::new(std::sync::Mutex::new(BlobUploadStats::default()));
    let publish_upload_stats = upload_stats_holder.clone();
    let all_blob_digests: Vec<String> = blobs.iter().map(|b| b.digest.clone()).collect();
    let confirm_outcome = crate::serve::cas_publish::publish_after_save_requiring_receipts(
        &state.api_client,
        &state.workspace,
        &save_response,
        manifest_root_digest.clone(),
        manifest_root_digest.clone(),
        expected_manifest_size,
        Some(all_blob_digests),
        |save_response| {
            let cache_entry_id = save_response.cache_entry_id.clone();
            let upload_session_id = save_response.upload_session_id.clone();
            async move {
                let upload_stats = if !blobs.is_empty() {
                    match upload_blobs(state, &cache_entry_id, &blobs, local_blob_paths)
                        .await
                    {
                        Ok(upload_stats) => upload_stats,
                        Err(error) => {
                            if let Some(partial_stats) = partial_blob_upload_stats(&error) {
                                if let Err(commit_error) = try_commit_blob_receipts(
                                    &state.api_client,
                                    &state.workspace,
                                    upload_session_id.as_deref(),
                                    partial_stats.uploaded_receipts.clone(),
                                )
                                .await
                                {
                                    log::warn!(
                                        "KV flush: partial blob receipt commit failed: {commit_error:#}"
                                    );
                                }
                                if partial_stats.uploaded_count > 0
                                    || partial_stats.missing_local_count > 0
                                {
                                    eprintln!(
                                        "KV flush: preserved partial blob uploads uploaded={} already_present={} missing_local={}",
                                        partial_stats.uploaded_count,
                                        partial_stats.already_present_count,
                                        partial_stats.missing_local_count
                                    );
                                }
                                *publish_upload_stats.lock().unwrap() = partial_stats;
                            }
                            return Err(classify_flush_error(&error, "blob upload failed"));
                        }
                    }
                } else {
                    BlobUploadStats::default()
                };

                *publish_upload_stats.lock().unwrap() = upload_stats.clone();
                Ok(upload_stats.uploaded_receipts)
            }
        },
        |save_response| {
            let manifest_upload_url = save_response.manifest_upload_url.clone();
            let upload_headers = save_response.upload_headers.clone();
            async move {
                let manifest_upload_url = manifest_upload_url
                    .as_ref()
                    .ok_or(FlushError::Permanent("missing manifest upload URL".into()))?;

                upload_payload(
                    state.api_client.transfer_client(),
                    manifest_upload_url,
                    &pointer_bytes,
                    "application/cbor",
                    &upload_headers,
                )
                .await
                .map_err(|e| classify_flush_error(&e, "manifest upload failed"))
            }
        },
        |manifest_etag| async move {
            let confirm_request = ConfirmRequest {
                manifest_digest: confirm_manifest_digest.clone(),
                manifest_size: expected_manifest_size,
                manifest_etag,
                archive_size: None,
                archive_etag: None,
                blob_count: Some(blob_count),
                blob_total_size_bytes: Some(blob_total_size_bytes),
                file_count: Some(file_count),
                uncompressed_size: None,
                compressed_size: None,
                storage_mode: Some("cas".to_string()),
                tag: Some(confirm_tag.clone()),
                write_scope_tag: confirm_write_scope_tag.clone(),
            };

            confirm_kv_flush(state, &confirm_cache_entry_id, &confirm_request).await
        },
        |message| FlushError::Transient(format!("receipt commit failed: {message}")),
    )
    .await?;
    let upload_stats = upload_stats_holder.lock().unwrap().clone();

    let alias_count = if publish_plan.stable {
        bind_kv_alias_tags(state, &confirm_outcome.cache_entry_id, Some(&tag)).await?
    } else {
        0
    };
    if diagnostics {
        eprintln!(
            "KV flush publish: tag={} cache_entry_id={} state={} alias_tags={}",
            tag,
            confirm_outcome.cache_entry_id,
            if publish_plan.stable {
                "stable"
            } else {
                "checkpoint"
            },
            alias_count
        );
    }

    if diagnostics && alias_count > 0 {
        eprintln!(
            "KV alias publish completed: cache_entry_id={} alias_tags={}",
            confirm_outcome.cache_entry_id, alias_count
        );
    }

    if diagnostics {
        eprintln!(
            "KV flush summary: entries={} unique_blobs={} uploaded={} already_present={} skipped_local={} bytes={} duration_ms={}",
            total_count,
            blob_count,
            upload_stats.uploaded_count,
            upload_stats.already_present_count,
            upload_stats.missing_local_count,
            blob_total_size_bytes,
            flush_started_at.elapsed().as_millis()
        );
    }

    Ok(confirm_outcome.cache_entry_id)
}

async fn checkpoint_kv_blobs(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
    diagnostics: bool,
    flush_started_at: std::time::Instant,
) -> Result<String, FlushError> {
    let pending_blob_order = merge_blob_order(pending_entries, &[]);
    let (checkpoint_pointer_bytes, pending_blobs) =
        build_index_pointer(pending_entries, &pending_blob_order).map_err(|e| {
            FlushError::Transient(format!("build checkpoint pointer failed: {e:?}"))
        })?;

    let checkpoint_digest = crate::cas_file::prefixed_sha256_digest(&checkpoint_pointer_bytes);
    let expected_manifest_size = checkpoint_pointer_bytes.len() as u64;
    let blob_count = pending_blobs.len() as u64;
    let blob_total_size_bytes: u64 = pending_blobs.iter().map(|b| b.size_bytes).sum();
    let file_count = pending_entries.len().min(u32::MAX as usize) as u32;
    let request = kv_save_request(
        state,
        String::new(),
        None,
        checkpoint_digest.clone(),
        expected_manifest_size,
        blob_count,
        blob_total_size_bytes,
        file_count,
    );

    let save_response = save_kv_entry(state, &request).await?;
    if let Some(reason) = save_response.blocking_pending_cas_reason(&checkpoint_digest) {
        return Err(FlushError::Conflict(format!(
            "checkpoint save_entry failed: another cache upload is in progress ({reason})"
        )));
    }

    let upload_stats = if pending_blobs.is_empty() {
        BlobUploadStats::default()
    } else {
        match upload_blobs(
            state,
            &save_response.cache_entry_id,
            &pending_blobs,
            pending_blob_paths,
        )
        .await
        {
            Ok(upload_stats) => upload_stats,
            Err(error) => {
                if let Some(partial_stats) = partial_blob_upload_stats(&error) {
                    if let Err(commit_error) = try_commit_blob_receipts(
                        &state.api_client,
                        &state.workspace,
                        save_response.upload_session_id.as_deref(),
                        partial_stats.uploaded_receipts.clone(),
                    )
                    .await
                    {
                        log::warn!(
                            "KV checkpoint: partial blob receipt commit failed: {commit_error:#}"
                        );
                    }
                    if partial_stats.uploaded_count > 0 || partial_stats.missing_local_count > 0 {
                        eprintln!(
                            "KV checkpoint: preserved partial blob uploads uploaded={} already_present={} missing_local={}",
                            partial_stats.uploaded_count,
                            partial_stats.already_present_count,
                            partial_stats.missing_local_count
                        );
                    }
                }
                return Err(classify_flush_error(
                    &error,
                    "checkpoint blob upload failed",
                ));
            }
        }
    };

    commit_required_blob_receipts(
        state,
        save_response.upload_session_id.as_deref(),
        upload_stats.uploaded_receipts.clone(),
        "checkpoint blob receipt commit failed",
    )
    .await?;

    if diagnostics {
        eprintln!(
            "KV checkpoint: cache_entry_id={} entries={} unique_blobs={} uploaded={} already_present={} skipped_local={} bytes={} duration_ms={}",
            save_response.cache_entry_id,
            pending_entries.len(),
            blob_count,
            upload_stats.uploaded_count,
            upload_stats.already_present_count,
            upload_stats.missing_local_count,
            blob_total_size_bytes,
            flush_started_at.elapsed().as_millis()
        );
    }

    Ok(save_response.cache_entry_id)
}

async fn commit_required_blob_receipts(
    state: &AppState,
    upload_session_id: Option<&str>,
    receipts: Vec<crate::api::models::cache::BlobReceipt>,
    context: &str,
) -> Result<(), FlushError> {
    if receipts.is_empty() {
        return Ok(());
    }

    let Some(upload_session_id) = upload_session_id.filter(|value| !value.trim().is_empty()) else {
        return Err(FlushError::Transient(format!(
            "{context}: missing upload_session_id"
        )));
    };

    try_commit_blob_receipts(
        &state.api_client,
        &state.workspace,
        Some(upload_session_id),
        receipts,
    )
    .await
    .map_err(|error| classify_flush_error(&error, context))
}

#[allow(clippy::too_many_arguments)]
fn kv_save_request(
    state: &AppState,
    tag: String,
    write_scope_tag: Option<String>,
    manifest_root_digest: String,
    expected_manifest_size: u64,
    blob_count: u64,
    blob_total_size_bytes: u64,
    file_count: u32,
) -> SaveRequest {
    SaveRequest {
        tag,
        write_scope_tag,
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("file-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes: blob_total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(file_count),
        expected_manifest_digest: Some(manifest_root_digest),
        expected_manifest_size: Some(expected_manifest_size),
        force: None,
        use_multipart: None,
        ci_provider: state.ci_provider(),
        ci_run_uid: state.ci_run_uid(),
        ci_run_attempt: state.ci_run_attempt(),
        ci_ref_type: state.ci_ref_type(),
        ci_ref_name: state.ci_ref_name(),
        ci_default_branch: state.ci_default_branch(),
        ci_pr_number: state.ci_pr_number(),
        ci_commit_sha: state.ci_commit_sha(),
        ci_run_started_at: state.ci_run_started_at(),
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    }
}

async fn save_kv_entry(
    state: &AppState,
    request: &SaveRequest,
) -> Result<crate::api::models::cache::SaveResponse, FlushError> {
    match state.api_client.save_entry(&state.workspace, request).await {
        Ok(resp) => {
            state.backend_breaker.record_success();
            Ok(resp)
        }
        Err(e) => {
            state.backend_breaker.record_failure();
            Err(classify_flush_error(&e, "save_entry failed"))
        }
    }
}

fn local_reconcile_blobs(
    entries: &BTreeMap<String, BlobDescriptor>,
    local_blob_paths: &HashMap<String, PathBuf>,
) -> Vec<BlobDescriptor> {
    let mut blobs_by_digest: BTreeMap<String, u64> = BTreeMap::new();
    for blob in entries.values() {
        if local_blob_paths.contains_key(&blob.digest) {
            blobs_by_digest
                .entry(blob.digest.clone())
                .or_insert(blob.size_bytes);
        }
    }

    blobs_by_digest
        .into_iter()
        .map(|(digest, size_bytes)| BlobDescriptor { digest, size_bytes })
        .collect()
}

type FilteredPendingEntries = (
    BTreeMap<String, BlobDescriptor>,
    HashMap<String, PathBuf>,
    Vec<String>,
    usize,
);

pub(crate) fn filter_pending_entries_with_local_blobs(
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> FilteredPendingEntries {
    let mut missing_digests = HashSet::new();
    let mut filtered_blob_paths = HashMap::new();

    for blob in pending_entries.values() {
        if missing_digests.contains(&blob.digest) || filtered_blob_paths.contains_key(&blob.digest)
        {
            continue;
        }

        let Some(path) = pending_blob_paths.get(&blob.digest) else {
            missing_digests.insert(blob.digest.clone());
            continue;
        };

        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {
                filtered_blob_paths.insert(blob.digest.clone(), path.clone());
            }
            Ok(_) => {
                missing_digests.insert(blob.digest.clone());
            }
            Err(_) => {
                missing_digests.insert(blob.digest.clone());
            }
        }
    }

    let mut filtered_entries = BTreeMap::new();
    let mut missing_entry_count = 0usize;
    for (key, blob) in pending_entries {
        if missing_digests.contains(&blob.digest) {
            missing_entry_count = missing_entry_count.saturating_add(1);
            continue;
        }
        filtered_entries.insert(key.clone(), blob.clone());
    }

    (
        filtered_entries,
        filtered_blob_paths,
        missing_digests.into_iter().collect(),
        missing_entry_count,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bind_kv_alias_tag(
    state: &AppState,
    alias_tag: &str,
    cache_entry_id: &str,
) -> anyhow::Result<()> {
    state
        .api_client
        .publish_ready_tag(
            &state.workspace,
            alias_tag,
            cache_entry_id,
            kv_primary_write_scope_tag(state),
            "cas",
        )
        .await
        .map(|_| ())
}

pub(crate) async fn bind_kv_alias_tags(
    state: &AppState,
    cache_entry_id: &str,
    skip_tag: Option<&str>,
) -> Result<usize, FlushError> {
    let mut alias_count = 0usize;
    for alias_tag in kv_alias_tags(state) {
        if skip_tag == Some(alias_tag.as_str()) {
            continue;
        }

        let bind_result = bind_kv_alias_tag(state, &alias_tag, cache_entry_id).await;
        match bind_result {
            Ok(()) => {
                alias_count = alias_count.saturating_add(1);
            }
            Err(error) => {
                if state.fail_on_cache_error || server_cache_tag_name(&alias_tag) {
                    let stage = format!("alias bind failed for tag {alias_tag}");
                    return Err(classify_flush_error(&error, &stage));
                }
                log::warn!("KV flush: alias bind failed for tag {alias_tag}: {error}");
            }
        }
    }
    Ok(alias_count)
}

pub(crate) async fn promote_kv_published_checkpoint_on_shutdown(state: &AppState) -> FlushResult {
    let (entries, blob_order) = {
        let published = state.kv_published_index.read().await;
        if published.is_stable() {
            return FlushResult::Ok;
        }

        let entries: BTreeMap<String, BlobDescriptor> = published
            .entries_snapshot()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if entries.is_empty() {
            return FlushResult::Ok;
        }
        (entries, published.unique_blobs())
    };

    let diagnostics = crate::serve::state::diagnostics_enabled();
    let publish_plan = kv_flush_publish_plan(state, FlushMode::Shutdown).await;
    let local_blob_paths = HashMap::new();

    match publish_kv_manifest(
        state,
        &entries,
        &blob_order,
        &local_blob_paths,
        &publish_plan,
        diagnostics,
        std::time::Instant::now(),
    )
    .await
    {
        Ok(cache_entry_id) => {
            {
                let mut published = state.kv_published_index.write().await;
                published.update(
                    entries.into_iter().collect(),
                    blob_order,
                    cache_entry_id.clone(),
                    true,
                );
            }
            if diagnostics {
                eprintln!(
                    "KV shutdown publish: published checkpoint cache_entry_id={}",
                    cache_entry_id
                );
            }
            FlushResult::Ok
        }
        Err(error) => {
            eprintln!("KV shutdown publish failed: {error:?}");
            match error {
                FlushError::Conflict(_) => FlushResult::Conflict,
                FlushError::Transient(_) => FlushResult::Error,
                FlushError::Permanent(_) => FlushResult::Permanent,
            }
        }
    }
}

pub(crate) fn server_cache_tag_name(tag: &str) -> bool {
    crate::tag_utils::server_cache_tag_name(tag)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlushBaseSelection {
    Backend,
    PublishedFallback {
        backend_entry_count: usize,
        published_entry_count: usize,
        missing_published_keys: usize,
        mismatched_published_keys: usize,
    },
}

pub(crate) fn select_flush_base_entries(
    backend_entries: BTreeMap<String, BlobDescriptor>,
    published_entries: &HashMap<String, BlobDescriptor>,
) -> (BTreeMap<String, BlobDescriptor>, FlushBaseSelection) {
    if backend_entries.is_empty() && !published_entries.is_empty() {
        return (
            published_entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 0,
                published_entry_count: published_entries.len(),
                missing_published_keys: published_entries.len(),
                mismatched_published_keys: 0,
            },
        );
    }
    if backend_entries.is_empty() || published_entries.is_empty() {
        return (backend_entries, FlushBaseSelection::Backend);
    }

    let mut missing_published_keys = 0usize;
    let mut mismatched_published_keys = 0usize;
    for (key, published_blob) in published_entries {
        match backend_entries.get(key) {
            Some(backend_blob)
                if backend_blob.digest == published_blob.digest
                    && backend_blob.size_bytes == published_blob.size_bytes => {}
            Some(_) => {
                mismatched_published_keys = mismatched_published_keys.saturating_add(1);
            }
            None => {
                missing_published_keys = missing_published_keys.saturating_add(1);
            }
        }
    }

    if missing_published_keys == 0 && mismatched_published_keys == 0 {
        return (backend_entries, FlushBaseSelection::Backend);
    }

    let backend_entry_count = backend_entries.len();
    let published_entry_count = published_entries.len();
    // Backend reads can lag right after publish; preserve local monotonic state to avoid pointer shrink.
    let mut merged = backend_entries;
    for (key, value) in published_entries {
        merged.insert(key.clone(), value.clone());
    }

    (
        merged,
        FlushBaseSelection::PublishedFallback {
            backend_entry_count,
            published_entry_count,
            missing_published_keys,
            mismatched_published_keys,
        },
    )
}

#[cfg(test)]
mod flush_tests {
    use super::*;

    #[test]
    fn normal_flush_does_not_publish_stable_manifest() {
        assert!(!FlushMode::Normal.publishes_stable_manifest());
        assert!(FlushMode::Shutdown.publishes_stable_manifest());
    }

    #[test]
    fn local_reconcile_blobs_only_includes_blobs_with_local_paths() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        entries.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        entries.insert(
            "k3".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let mut local_blob_paths = HashMap::new();
        local_blob_paths.insert("sha256:111".to_string(), PathBuf::from("/tmp/blob-111"));

        let blobs = local_reconcile_blobs(&entries, &local_blob_paths);

        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].digest, "sha256:111");
        assert_eq!(blobs[0].size_bytes, 10);
    }
}

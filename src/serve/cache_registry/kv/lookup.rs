use super::*;

pub(crate) async fn lookup_published_blob(
    state: &AppState,
    scoped_key: &str,
) -> Option<(BlobDescriptor, String, Option<String>)> {
    let published = state.kv_published_index.read().await;
    let (blob, cache_entry_id) = published.get(scoped_key)?;
    let blob = blob.clone();
    let cache_entry_id = cache_entry_id.to_string();
    let cached_url = published.download_url(&blob.digest).map(str::to_string);
    Some((blob, cache_entry_id, cached_url))
}

pub(crate) async fn populate_sizes_from_published(
    state: &AppState,
    scoped_keys: &[String],
    sizes: &mut HashMap<String, u64>,
) {
    let published = state.kv_published_index.read().await;
    for scoped in scoped_keys {
        if sizes.contains_key(scoped) {
            continue;
        }
        if let Some((blob, _)) = published.get(scoped) {
            sizes.insert(scoped.clone(), blob.size_bytes);
        }
    }
}

pub(crate) fn content_length_bytes(response: &Response) -> u64 {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

pub(crate) fn expected_bazel_cas_blob_digest(namespace: KvNamespace, key: &str) -> Option<String> {
    if !matches!(namespace, KvNamespace::BazelCas) {
        return None;
    }
    Some(format!("sha256:{}", namespace.normalize_key(key)))
}

pub(crate) fn bazel_cas_blob_matches(
    namespace: KvNamespace,
    key: &str,
    blob: &BlobDescriptor,
) -> bool {
    match expected_bazel_cas_blob_digest(namespace, key) {
        Some(expected) => blob.digest.eq_ignore_ascii_case(&expected),
        None => true,
    }
}

pub(crate) async fn get_or_head_kv_object(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let get_start = std::time::Instant::now();
    let result = get_or_head_kv_object_inner(state, namespace, key, is_head).await;
    let elapsed_ms = get_start.elapsed().as_millis() as u64;
    let tool = namespace.into();

    match &result {
        Ok(response) => {
            state.cache_ops.record(
                tool,
                super::super::cache_ops::Op::Get,
                super::super::cache_ops::OpResult::Hit,
                false,
                content_length_bytes(response),
                elapsed_ms,
            );
        }
        Err(e) if e.status == StatusCode::NOT_FOUND => {
            state.cache_ops.record(
                tool,
                super::super::cache_ops::Op::Get,
                super::super::cache_ops::OpResult::Miss,
                false,
                0,
                elapsed_ms,
            );
            state.cache_ops.record_miss(tool, key);
        }
        Err(error) => {
            let degraded = !state.fail_on_cache_error && error.status.is_server_error();
            state.cache_ops.record(
                tool,
                super::super::cache_ops::Op::Get,
                super::super::cache_ops::OpResult::Error,
                degraded,
                0,
                elapsed_ms,
            );
        }
    }

    result
}

pub(crate) async fn await_startup_prefetch_readiness(
    state: &AppState,
) -> Result<(), RegistryError> {
    loop {
        if state.prefetch_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        if let Some(message) = state.prefetch_error.read().await.clone() {
            return Err(RegistryError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Cache registry startup warmup failed: {message}"),
            ));
        }

        let notified = state.prefetch_complete_notify.notified();
        if state.prefetch_complete.load(Ordering::Acquire) {
            return Ok(());
        }

        if let Some(message) = state.prefetch_error.read().await.clone() {
            return Err(RegistryError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Cache registry startup warmup failed: {message}"),
            ));
        }

        match tokio::time::timeout(KV_PREFETCH_READINESS_TIMEOUT, notified).await {
            Ok(()) => {
                if let Some(message) = state.prefetch_error.read().await.clone() {
                    return Err(RegistryError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Cache registry startup warmup failed: {message}"),
                    ));
                }
            }
            Err(_) => {
                return Err(RegistryError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "Cache registry is still warming after {}s",
                        KV_PREFETCH_READINESS_TIMEOUT.as_secs()
                    ),
                ));
            }
        }
    }
}

pub(crate) async fn get_or_head_kv_object_inner(
    state: &AppState,
    namespace: KvNamespace,
    key: &str,
    is_head: bool,
) -> Result<Response, RegistryError> {
    let scoped_key = namespace.scoped_key(key);
    kv_trace(namespace, &scoped_key, "start");
    let use_miss_cache = use_kv_miss_cache(namespace);
    let miss_key = kv_miss_cache_key(state, &state.registry_root_tag, &scoped_key);

    let local = {
        let pending = state.kv_pending.read().await;
        pending.get(&scoped_key).and_then(|blob| {
            pending
                .blob_path(&blob.digest)
                .map(|path| (blob.clone(), path.clone()))
        })
    };
    kv_trace(namespace, &scoped_key, "after-pending");

    if let Some((blob, path)) = local {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-local");
            match serve_local_blob(&blob, &path, is_head).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("KV local blob read failed, falling back to backend: {e:?}");
                }
            }
        } else {
            log::warn!(
                "Bazel CAS local blob digest mismatch: key={} digest={}",
                key,
                blob.digest
            );
        }
    }

    let flushing_local = {
        let flushing = state.kv_flushing.read().await;
        flushing.as_ref().and_then(|snapshot| {
            snapshot.get(&scoped_key).and_then(|blob| {
                snapshot
                    .blob_path(&blob.digest)
                    .map(|path| (blob.clone(), path.clone()))
            })
        })
    };
    kv_trace(namespace, &scoped_key, "after-flushing");

    if let Some((blob, path)) = flushing_local {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-flushing");
            match serve_local_blob(&blob, &path, is_head).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("KV flushing blob read failed, falling through: {e:?}");
                }
            }
        } else {
            log::warn!(
                "Bazel CAS flushing blob digest mismatch: key={} digest={}",
                key,
                blob.digest
            );
        }
    }

    await_startup_prefetch_readiness(state).await?;

    if let Some((blob, cache_entry_id, cached_url)) =
        lookup_published_blob(state, &scoped_key).await
    {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-published-fast");
            if use_miss_cache {
                clear_kv_miss(state, &miss_key);
            }
            return serve_backend_blob(
                state,
                &cache_entry_id,
                &blob,
                cached_url.as_deref(),
                is_head,
            )
            .await;
        }
        log::warn!(
            "Bazel CAS published blob digest mismatch: key={} digest={}",
            key,
            blob.digest
        );
    }

    if use_miss_cache && is_recent_kv_miss(state, &miss_key) {
        kv_trace(namespace, &scoped_key, "recent-miss");
        return Err(RegistryError::not_found("Cache key not found"));
    }

    kv_trace(namespace, &scoped_key, "lookup-flight-begin");
    let lookup_result = match begin_lookup_flight(state, miss_key.clone()) {
        LookupFlight::Follower(notified) => {
            kv_trace(namespace, &scoped_key, "lookup-flight-follower-wait");
            if !await_flight("kv", &miss_key, notified).await {
                clear_lookup_flight_entry(state, &miss_key);
            }
            kv_trace(namespace, &scoped_key, "lookup-flight-follower-after-wait");
            lookup_published_blob(state, &scoped_key).await
        }
        LookupFlight::Leader(_lookup_guard) => {
            if use_miss_cache && is_recent_kv_miss(state, &miss_key) {
                kv_trace(namespace, &scoped_key, "leader-recent-miss");
                return Err(RegistryError::not_found("Cache key not found"));
            }

            if let Some(found) = lookup_published_blob(state, &scoped_key).await {
                kv_trace(namespace, &scoped_key, "leader-published-hit");
                Some(found)
            } else {
                kv_trace(namespace, &scoped_key, "leader-before-refresh");
                maybe_refresh_published_index_for_lookup(state).await?;
                kv_trace(namespace, &scoped_key, "leader-after-refresh");
                let result = lookup_published_blob(state, &scoped_key).await;
                if use_miss_cache && result.is_none() {
                    mark_kv_miss(state, &miss_key);
                    kv_trace(namespace, &scoped_key, "leader-mark-miss");
                }
                result
            }
            // _lookup_guard drops here — BEFORE the download
        }
    };
    kv_trace(namespace, &scoped_key, "lookup-flight-end");

    if let Some((blob, cache_entry_id, cached_url)) = lookup_result {
        if bazel_cas_blob_matches(namespace, key, &blob) {
            kv_trace(namespace, &scoped_key, "serve-published-after-lookup");
            if use_miss_cache {
                clear_kv_miss(state, &miss_key);
            }
            return serve_backend_blob(
                state,
                &cache_entry_id,
                &blob,
                cached_url.as_deref(),
                is_head,
            )
            .await;
        }
        log::warn!(
            "Bazel CAS lookup blob digest mismatch: key={} digest={}",
            key,
            blob.digest
        );
    }

    kv_trace(namespace, &scoped_key, "not-found");
    Err(RegistryError::not_found("Cache key not found"))
}

pub(crate) async fn resolve_kv_entries(
    state: &AppState,
    namespace: KvNamespace,
    keys: &[&str],
) -> Result<HashMap<String, u64>, RegistryError> {
    let query_start = std::time::Instant::now();
    let result = resolve_kv_entries_inner(state, namespace, keys).await;
    let elapsed_ms = query_start.elapsed().as_millis() as u64;
    let tool = namespace.into();

    if let Ok(sizes) = &result {
        for key in keys {
            let scoped = namespace.scoped_key(key);
            if let Some(&size) = sizes.get(&scoped) {
                state.cache_ops.record(
                    tool,
                    super::super::cache_ops::Op::Query,
                    super::super::cache_ops::OpResult::Hit,
                    false,
                    size,
                    elapsed_ms,
                );
            } else {
                state.cache_ops.record(
                    tool,
                    super::super::cache_ops::Op::Query,
                    super::super::cache_ops::OpResult::Miss,
                    false,
                    0,
                    elapsed_ms,
                );
                state.cache_ops.record_miss(tool, key);
            }
        }
    }

    result
}

pub(crate) async fn resolve_kv_entries_inner(
    state: &AppState,
    namespace: KvNamespace,
    keys: &[&str],
) -> Result<HashMap<String, u64>, RegistryError> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    let mut sizes = HashMap::new();
    let scoped_keys: Vec<String> = keys.iter().map(|k| namespace.scoped_key(k)).collect();

    {
        let pending = state.kv_pending.read().await;
        for scoped in &scoped_keys {
            if let Some(blob) = pending.get(scoped) {
                sizes.insert(scoped.clone(), blob.size_bytes);
            }
        }
    }

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    {
        let flushing = state.kv_flushing.read().await;
        if let Some(snapshot) = flushing.as_ref() {
            for scoped in &scoped_keys {
                if sizes.contains_key(scoped) {
                    continue;
                }
                if let Some(blob) = snapshot.get(scoped) {
                    sizes.insert(scoped.clone(), blob.size_bytes);
                }
            }
        }
    }

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;

    if sizes.len() == scoped_keys.len() {
        return Ok(sizes);
    }

    let sizes_key = lookup_flight_key_for_sizes(&scoped_keys);
    match begin_lookup_flight(state, sizes_key.clone()) {
        LookupFlight::Follower(notified) => {
            if !await_flight("sizes", &sizes_key, notified).await {
                clear_lookup_flight_entry(state, &sizes_key);
            }
            populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
            Ok(sizes)
        }
        LookupFlight::Leader(_lookup_flight) => {
            populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
            if sizes.len() == scoped_keys.len() {
                return Ok(sizes);
            }

            maybe_refresh_published_index_for_lookup(state).await?;

            populate_sizes_from_published(state, &scoped_keys, &mut sizes).await;
            Ok(sizes)
        }
    }
}

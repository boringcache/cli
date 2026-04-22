use super::*;

pub(crate) async fn cleanup_blob_files(paths: &HashMap<String, PathBuf>) {
    let removals = paths.values().map(tokio::fs::remove_file);
    for result in join_all(removals).await {
        if let Err(error) = result {
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            log::warn!("KV cleanup: failed to remove blob temp file: {error}");
        }
    }
}

pub(crate) async fn cleanup_paths(paths: Vec<PathBuf>) {
    let removals = paths.into_iter().map(tokio::fs::remove_file);
    for result in join_all(removals).await {
        if let Err(error) = result {
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            log::warn!("KV cleanup: failed to remove temp file: {error}");
        }
    }
}

pub(crate) async fn promote_pending_blobs_to_read_cache(
    state: &AppState,
    pending_entries: &BTreeMap<String, BlobDescriptor>,
    pending_blob_paths: &HashMap<String, PathBuf>,
) -> usize {
    let mut blob_sizes = HashMap::new();
    for blob in pending_entries.values() {
        blob_sizes
            .entry(blob.digest.clone())
            .or_insert(blob.size_bytes);
    }

    let mut promoted = 0usize;
    for (digest, path) in pending_blob_paths {
        let size = blob_sizes.get(digest).copied().unwrap_or(0);
        match state.blob_read_cache.promote(digest, path, size).await {
            Ok(true) => promoted = promoted.saturating_add(1),
            Ok(false) => {}
            Err(error) => {
                log::warn!("KV blob read cache promote failed for {digest}: {error}");
            }
        }
    }
    promoted
}

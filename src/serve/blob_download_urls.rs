use std::collections::HashMap;
use std::time::Duration;

use crate::api::models::cache::BlobDescriptor;
use crate::serve::state::AppState;

pub(crate) struct ResolvedBlobDownloadUrls {
    pub(crate) urls: HashMap<String, String>,
    pub(crate) missing: Vec<String>,
}

pub(crate) async fn resolve_verified_blob_download_urls(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    timeout: Duration,
) -> Result<ResolvedBlobDownloadUrls, String> {
    resolve_blob_download_urls(state, cache_entry_id, blobs, timeout, false).await
}

pub(crate) async fn resolve_live_verified_blob_download_urls(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    timeout: Duration,
) -> Result<ResolvedBlobDownloadUrls, String> {
    resolve_blob_download_urls(state, cache_entry_id, blobs, timeout, true).await
}

async fn resolve_blob_download_urls(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    timeout: Duration,
    live_storage: bool,
) -> Result<ResolvedBlobDownloadUrls, String> {
    let response = tokio::time::timeout(timeout, async {
        if live_storage {
            state
                .api_client
                .blob_download_urls_live_verified(&state.workspace, cache_entry_id, blobs)
                .await
        } else {
            state
                .api_client
                .blob_download_urls_verified(&state.workspace, cache_entry_id, blobs)
                .await
        }
    })
    .await
    .map_err(|_| format!("timed out after {}s", timeout.as_secs()))?
    .map_err(|error| error.to_string())?;

    let mut urls = HashMap::with_capacity(response.download_urls.len());
    for entry in response.download_urls {
        urls.insert(entry.digest, entry.url);
    }

    let mut missing = response.missing;
    for blob in blobs {
        if !urls.contains_key(blob.digest.as_str()) {
            missing.push(blob.digest.clone());
        }
    }
    missing.sort();
    missing.dedup();

    Ok(ResolvedBlobDownloadUrls { urls, missing })
}

pub(crate) async fn resolve_verified_blob_download_url(
    state: &AppState,
    cache_entry_id: &str,
    blob: &BlobDescriptor,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let mut resolved = resolve_verified_blob_download_urls(
        state,
        cache_entry_id,
        std::slice::from_ref(blob),
        timeout,
    )
    .await?;
    if resolved.missing.iter().any(|digest| digest == &blob.digest) {
        return Ok(None);
    }
    resolved
        .urls
        .remove(&blob.digest)
        .ok_or_else(|| format!("download URL missing for {}", blob.digest))
        .map(Some)
}

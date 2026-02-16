use anyhow::{Context, Result};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::sync::Semaphore;

use crate::progress::TransferProgress;
use crate::telemetry::StorageMetrics;
use crate::transfer::send_transfer_request_with_retry;

const PARALLEL_DOWNLOAD_THRESHOLD: u64 = 8 * 1024 * 1024;

pub(crate) async fn upload_payload(
    client: &reqwest::Client,
    url: &str,
    data: &[u8],
    content_type: &str,
    upload_headers: &HashMap<String, String>,
) -> Result<Option<String>> {
    let response = send_transfer_request_with_retry("Manifest upload", || async {
        let mut request = client.put(url).timeout(std::time::Duration::from_secs(300));

        if !has_header(upload_headers, "content-type") {
            request = request.header("Content-Type", content_type);
        }
        if !has_header(upload_headers, "content-length") {
            request = request.header("Content-Length", data.len().to_string());
        }

        for (key, value) in upload_headers {
            request = request.header(key.as_str(), value.as_str());
        }

        request
            .body(data.to_vec())
            .send()
            .await
            .with_context(|| format!("Failed to send upload request (URL: {})", url))
    })
    .await?;

    let status = response.status();
    let headers = response.headers().clone();

    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read response body".to_string());
        anyhow::bail!("Failed to upload payload: HTTP {} - {}", status, body);
    }

    Ok(headers
        .get("etag")
        .and_then(|etag| etag.to_str().ok())
        .map(|etag| etag.trim_matches('"').to_string()))
}

fn has_header(headers: &HashMap<String, String>, target: &str) -> bool {
    headers.keys().any(|key| key.eq_ignore_ascii_case(target))
}

pub(crate) async fn download_blob_file(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    progress: Option<&TransferProgress>,
    expected_size: u64,
    writer_capacity: usize,
    expected_digest: Option<&str>,
) -> Result<(u64, StorageMetrics)> {
    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    if expected_size >= PARALLEL_DOWNLOAD_THRESHOLD {
        let result = download_parallel(client, url, file_path, expected_size, progress).await?;
        if let Some(digest) = expected_digest {
            verify_blob_digest(file_path, digest).await?;
        }
        return Ok(result);
    }

    download_sequential(
        client,
        url,
        file_path,
        progress,
        expected_size,
        writer_capacity,
        expected_digest,
    )
    .await
}

async fn verify_blob_digest(file_path: &Path, expected_digest: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let hex_digest = expected_digest
        .strip_prefix("sha256:")
        .unwrap_or(expected_digest);

    let file = tokio::fs::File::open(file_path)
        .await
        .with_context(|| format!("Failed to open {} for integrity check", file_path.display()))?;

    let mut reader = tokio::io::BufReader::with_capacity(256 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let actual = hex::encode(hasher.finalize());

    if actual != hex_digest {
        anyhow::bail!(
            "Blob integrity check failed for {}: expected sha256:{}, got sha256:{}",
            file_path.display(),
            hex_digest,
            actual,
        );
    }

    Ok(())
}

async fn download_sequential(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    progress: Option<&TransferProgress>,
    expected_size: u64,
    writer_capacity: usize,
    expected_digest: Option<&str>,
) -> Result<(u64, StorageMetrics)> {
    use sha2::{Digest, Sha256};

    let response = send_transfer_request_with_retry("Blob download", || async {
        Ok(client.get(url).send().await?)
    })
    .await?
    .error_for_status()
    .context("Blob download failed")?;

    let storage_metrics = StorageMetrics::from_headers(response.headers());

    let file = tokio::fs::File::create(file_path)
        .await
        .with_context(|| format!("Failed to create {}", file_path.display()))?;
    let mut writer = BufWriter::with_capacity(writer_capacity, file);
    let mut bytes_downloaded = 0u64;
    let mut stream = response.bytes_stream();
    let mut hasher = expected_digest.map(|_| Sha256::new());

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        let len = chunk.len() as u64;
        if let Some(ref mut h) = hasher {
            h.update(&chunk);
        }
        writer.write_all(&chunk).await?;
        bytes_downloaded += len;
        if let Some(progress) = progress {
            let _ = progress.record_bytes(len);
        }
    }
    writer.flush().await?;

    if expected_size > 0 && bytes_downloaded != expected_size {
        anyhow::bail!(
            "Blob size mismatch for {} (expected {}, got {})",
            file_path.display(),
            expected_size,
            bytes_downloaded
        );
    }

    if let (Some(hasher), Some(digest)) = (hasher, expected_digest) {
        let hex_expected = digest.strip_prefix("sha256:").unwrap_or(digest);
        let actual = hex::encode(hasher.finalize());
        if actual != hex_expected {
            anyhow::bail!(
                "Blob integrity check failed for {}: expected sha256:{}, got sha256:{}",
                file_path.display(),
                hex_expected,
                actual,
            );
        }
    }

    Ok((bytes_downloaded, storage_metrics))
}

async fn download_parallel(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    total_size: u64,
    progress: Option<&TransferProgress>,
) -> Result<(u64, StorageMetrics)> {
    let probe = send_transfer_request_with_retry("Range probe", || async {
        Ok(client
            .get(url)
            .header(reqwest::header::RANGE, "bytes=0-0")
            .send()
            .await?)
    })
    .await?;

    if probe.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        log::debug!(
            "Range request returned {}, falling back to sequential download",
            probe.status()
        );
        return download_sequential(
            client,
            url,
            file_path,
            progress,
            total_size,
            download_buffer_size(),
            None,
        )
        .await;
    }
    drop(probe);

    let concurrency = calculate_download_concurrency();
    let min_part_size: u64 = 8 * 1024 * 1024;
    let max_part_size: u64 = 64 * 1024 * 1024;
    let target_parts = (concurrency * 2).max(8) as u64;
    let part_size = (total_size / target_parts).clamp(min_part_size, max_part_size);
    let num_parts = total_size.div_ceil(part_size);

    log::info!(
        "Parallel blob download: {} in {} parts ({} each), {} connections",
        crate::progress::format_bytes(total_size),
        num_parts,
        crate::progress::format_bytes(part_size),
        concurrency
    );

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)
        .await
        .context("Failed to create download file")?;
    file.set_len(total_size)
        .await
        .context("Failed to pre-allocate download file")?;
    drop(file);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(num_parts as usize);

    for part_idx in 0..num_parts {
        let start = part_idx * part_size;
        let end = std::cmp::min(start + part_size, total_size) - 1;
        let this_part_size = end - start + 1;

        let client = client.clone();
        let url = url.to_string();
        let file_path = file_path.to_path_buf();
        let semaphore = semaphore.clone();
        let progress = progress.cloned();
        let part_num = part_idx + 1;

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            download_range(
                &client,
                &url,
                &file_path,
                start,
                end,
                this_part_size,
                progress.as_ref(),
            )
            .await
            .with_context(|| {
                format!(
                    "Part {}/{} (bytes {}-{}) failed",
                    part_num, num_parts, start, end
                )
            })
        });

        tasks.push(task);
    }

    let mut total_downloaded = 0u64;
    let mut errors: Vec<String> = Vec::new();
    let mut first_storage_metrics: Option<StorageMetrics> = None;

    for (idx, task) in tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok((bytes, metrics))) => {
                total_downloaded += bytes;
                if first_storage_metrics.is_none() {
                    first_storage_metrics = Some(metrics);
                }
            }
            Ok(Err(e)) => errors.push(format!("Part {}: {}", idx + 1, e)),
            Err(e) => errors.push(format!("Part {} panicked: {}", idx + 1, e)),
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "Parallel download failed with {} errors:\n{}",
            errors.len(),
            errors.join("\n")
        );
    }

    Ok((total_downloaded, first_storage_metrics.unwrap_or_default()))
}

pub(crate) async fn download_range(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    start: u64,
    end: u64,
    expected_size: u64,
    progress: Option<&TransferProgress>,
) -> Result<(u64, StorageMetrics)> {
    let response = send_transfer_request_with_retry("Range download", || async {
        Ok(client
            .get(url)
            .header(reqwest::header::RANGE, format!("bytes={}-{}", start, end))
            .send()
            .await?)
    })
    .await?;

    let storage_metrics = StorageMetrics::from_headers(response.headers());

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        log::error!(
            "Download range {}-{} failed: HTTP {} - {}",
            start,
            end,
            status,
            error_body
        );
        anyhow::bail!(
            "HTTP {} - {}",
            status,
            if error_body.is_empty() {
                status.canonical_reason().unwrap_or("Unknown error")
            } else {
                &error_body
            }
        );
    }

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(file_path)
        .await
        .context("Failed to open file")?;

    let mut writer = BufWriter::with_capacity(download_buffer_size(), file);
    writer.seek(std::io::SeekFrom::Start(start)).await?;

    let mut bytes_written = 0u64;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        let len = chunk.len();
        writer.write_all(&chunk).await?;
        bytes_written += len as u64;

        if let Some(p) = progress {
            let _ = p.record_bytes(len as u64);
        }

        if bytes_written >= expected_size {
            break;
        }
    }

    writer.flush().await?;

    if bytes_written < expected_size {
        anyhow::bail!("Incomplete: {} < {}", bytes_written, expected_size);
    }

    Ok((expected_size, storage_metrics))
}

pub(crate) fn calculate_download_concurrency() -> usize {
    use crate::platform::resources::{DiskType, MemoryStrategy, SystemResources};

    let resources = SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();

    let base: usize = match resources.memory_strategy {
        MemoryStrategy::Balanced => 3,
        MemoryStrategy::Aggressive => 6,
        MemoryStrategy::UltraAggressive => 12,
    };

    let disk_adjusted: usize = match resources.disk_type {
        DiskType::NvmeSsd => base + 2,
        DiskType::SataSsd => base,
    };

    let cpu_scaled = disk_adjusted.min(resources.cpu_cores);

    if is_ci {
        cpu_scaled.clamp(2, 6)
    } else {
        cpu_scaled.clamp(4, 16)
    }
}

pub(crate) fn download_buffer_size() -> usize {
    use crate::platform::resources::{MemoryStrategy, SystemResources};

    match SystemResources::detect().memory_strategy {
        MemoryStrategy::Balanced => 512 * 1024,
        MemoryStrategy::Aggressive => 1024 * 1024,
        MemoryStrategy::UltraAggressive => 2 * 1024 * 1024,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify_blob_digest_accepts_valid_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        tokio::fs::write(&path, b"hello world").await.unwrap();
        verify_blob_digest(
            &path,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verify_blob_digest_rejects_wrong_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        tokio::fs::write(&path, b"hello world").await.unwrap();
        let result = verify_blob_digest(
            &path,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("integrity check failed"),);
    }

    #[tokio::test]
    async fn verify_blob_digest_handles_unprefixed_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        tokio::fs::write(&path, b"hello world").await.unwrap();
        verify_blob_digest(
            &path,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .await
        .unwrap();
    }
}

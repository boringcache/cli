use crate::api::models::cache::MultipartPart;
use crate::progress::TransferProgress;
use crate::telemetry::StorageMetrics;
use crate::transfer::send_transfer_request_with_retry;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::Client;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;

const STREAM_CHUNK_SIZE: usize = 2 * 1024 * 1024;

pub async fn upload_via_single_url(
    archive_path: &Path,
    upload_url: &str,
    progress: &TransferProgress,
    client: &Client,
    upload_headers: &HashMap<String, String>,
) -> Result<(Option<String>, StorageMetrics)> {
    let file_size = tokio::fs::metadata(archive_path)
        .await
        .with_context(|| format!("Failed to read archive metadata {}", archive_path.display()))?
        .len();

    let response = send_transfer_request_with_retry("Archive upload", || async {
        let file = File::open(archive_path)
            .await
            .with_context(|| format!("Failed to open archive {}", archive_path.display()))?;
        let reader = ReaderStream::with_capacity(file, STREAM_CHUNK_SIZE);
        let progress_clone = progress.clone();
        let stream = reader.map(move |chunk_result| match chunk_result {
            Ok(chunk) => {
                if let Err(err) = progress_clone.record_bytes(chunk.len() as u64) {
                    log::warn!("Failed to update upload progress: {err}");
                }
                Ok(chunk)
            }
            Err(err) => Err(err),
        });

        let mut request = client.put(upload_url);

        if !has_header(upload_headers, "content-type") {
            request = request.header("content-type", "application/octet-stream");
        }
        if !has_header(upload_headers, "content-length") {
            request = request.header("content-length", file_size.to_string());
        }

        for (key, value) in upload_headers {
            request = request.header(key.as_str(), value.as_str());
        }

        request
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .context("Failed to upload archive")
    })
    .await?;

    let storage_metrics = StorageMetrics::from_headers(response.headers());

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        log::error!("Single upload failed: HTTP {} - {}", status, error_body);
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

    Ok((extract_etag(&response), storage_metrics))
}

pub async fn upload_via_part_urls(
    archive_path: &Path,
    part_urls: &[String],
    progress: &TransferProgress,
    client: &Client,
    upload_headers: &HashMap<String, String>,
) -> Result<(Vec<MultipartPart>, StorageMetrics)> {
    anyhow::ensure!(!part_urls.is_empty(), "multipart upload URLs missing");

    let file_size = tokio::fs::metadata(archive_path).await?.len();
    let part_size = file_size.div_ceil(part_urls.len() as u64);

    let concurrency = calculate_upload_concurrency();
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let archive_path = archive_path.to_path_buf();
    let progress = progress.clone();
    let upload_headers = Arc::new(upload_headers.clone());

    let mut tasks = Vec::with_capacity(part_urls.len());

    for (idx, url) in part_urls.iter().enumerate() {
        let part_number = idx + 1;
        let offset = idx as u64 * part_size;
        let remaining = file_size.saturating_sub(offset);
        if remaining == 0 {
            break;
        }
        let size = remaining.min(part_size);

        let url = url.clone();
        let archive_path = archive_path.clone();
        let progress = progress.clone();
        let client = client.clone();
        let semaphore = semaphore.clone();
        let total_parts = part_urls.len();
        let upload_headers = upload_headers.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            let (etag, metrics) = upload_single_part(
                &archive_path,
                &url,
                part_number,
                offset,
                size,
                &progress,
                &client,
                &upload_headers,
            )
            .await
            .with_context(|| format!("Failed to upload part {part_number}/{total_parts}"))?;

            Ok::<(MultipartPart, StorageMetrics), anyhow::Error>((
                MultipartPart { part_number, etag },
                metrics,
            ))
        });

        tasks.push(task);
    }

    let mut uploaded_parts = Vec::with_capacity(tasks.len());
    let mut first_storage_metrics: Option<StorageMetrics> = None;

    for task in tasks {
        let (part, metrics) = task.await.context("Upload task panicked")??;
        if first_storage_metrics.is_none() {
            first_storage_metrics = Some(metrics);
        }
        uploaded_parts.push(part);
    }

    uploaded_parts.sort_by_key(|part| part.part_number);

    Ok((uploaded_parts, first_storage_metrics.unwrap_or_default()))
}

#[allow(clippy::too_many_arguments)]
async fn upload_single_part(
    archive_path: &Path,
    url: &str,
    part_number: usize,
    offset: u64,
    size: u64,
    progress: &TransferProgress,
    client: &Client,
    upload_headers: &HashMap<String, String>,
) -> Result<(String, StorageMetrics)> {
    log::info!(
        "Uploading part {} offset {} ({} bytes)",
        part_number,
        offset,
        size
    );

    let chunk_size = chunk_size_for_system();
    let operation_name = format!("Upload part {}", part_number);

    let response = send_transfer_request_with_retry(operation_name.as_str(), || async {
        let file = File::open(archive_path)
            .await
            .with_context(|| format!("Failed to open archive {}", archive_path.display()))?;
        let mut reader = tokio::io::BufReader::with_capacity(chunk_size, file);
        reader
            .seek(tokio::io::SeekFrom::Start(offset))
            .await
            .context("Failed to seek archive for multipart upload")?;

        let bytes_to_stream = size;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(4);
        let progress_clone = progress.clone();

        let send_task = tokio::spawn(async move {
            let mut reader = reader;
            let mut remaining = bytes_to_stream;
            while remaining > 0 {
                let to_read = remaining.min(chunk_size as u64) as usize;
                let mut buffer = vec![0u8; to_read];
                if let Err(err) = reader.read_exact(&mut buffer).await {
                    let _ = tx.send(Err(err)).await;
                    return;
                }
                remaining -= to_read as u64;
                if tx.send(Ok(buffer)).await.is_err() {
                    return;
                }
                if let Err(err) = progress_clone.record_bytes(to_read as u64) {
                    log::warn!("Failed to update multipart progress: {err}");
                }
            }
        });

        let mut request = client.put(url);

        if !has_header(upload_headers, "content-type") {
            request = request.header("content-type", "application/octet-stream");
        }
        if !has_header(upload_headers, "content-length") {
            request = request.header("content-length", size.to_string());
        }

        for (key, value) in upload_headers.iter() {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request
            .body(reqwest::Body::wrap_stream(ReceiverStream::new(rx)))
            .send()
            .await
            .with_context(|| format!("Failed to upload part {}", part_number))?;

        let _ = send_task.await;

        Ok(response)
    })
    .await?;

    let storage_metrics = StorageMetrics::from_headers(response.headers());

    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        log::error!(
            "Upload part {} failed: HTTP {} - {}",
            part_number,
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

    let etag = extract_etag(&response)
        .ok_or_else(|| anyhow::anyhow!("Upload response missing ETag for part {}", part_number))?;

    Ok((etag, storage_metrics))
}

fn extract_etag(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get("etag")
        .and_then(|header| header.to_str().ok())
        .map(|etag| etag.trim_matches('"').to_string())
}

fn chunk_size_for_system() -> usize {
    match crate::platform::resources::SystemResources::detect().memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => 2 * 1024 * 1024,
        crate::platform::resources::MemoryStrategy::Aggressive => 4 * 1024 * 1024,
        crate::platform::resources::MemoryStrategy::UltraAggressive => 8 * 1024 * 1024,
    }
}

fn has_header(headers: &HashMap<String, String>, target: &str) -> bool {
    headers.keys().any(|key| key.eq_ignore_ascii_case(target))
}

fn calculate_upload_concurrency() -> usize {
    use crate::platform::resources::{DiskType, MemoryStrategy, SystemResources};

    let resources = SystemResources::detect();

    let base_concurrency: usize = match resources.memory_strategy {
        MemoryStrategy::Balanced => 2,
        MemoryStrategy::Aggressive => 3,
        MemoryStrategy::UltraAggressive => 4,
    };

    let disk_adjusted: usize = match resources.disk_type {
        DiskType::NvmeSsd => base_concurrency + 1,
        DiskType::SataSsd => base_concurrency,
    };

    let cpu_adjusted: usize = if resources.cpu_load_percent > 75.0 {
        disk_adjusted.saturating_sub(1).max(1)
    } else {
        disk_adjusted
    };

    cpu_adjusted.min(6)
}

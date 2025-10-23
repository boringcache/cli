use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::Client;

use crate::platform::SystemResources;

pub fn get_multipart_threshold() -> u64 {
    SystemResources::detect().multipart_threshold()
}

pub fn should_use_multipart(size: u64) -> bool {
    size > get_multipart_threshold()
}

pub async fn http_request_with_validation(
    request: reqwest::RequestBuilder,
    operation: &str,
) -> Result<reqwest::Response> {
    let response = request
        .send()
        .await
        .with_context(|| format!("Failed to {operation}"))?;

    if !response.status().is_success() {
        anyhow::bail!("{} failed with status: {}", operation, response.status());
    }

    Ok(response)
}

pub async fn download_file(url: &str, file_path: &std::path::Path) -> Result<()> {
    let client = Client::new();
    let response = http_request_with_validation(client.get(url), "Download file").await?;

    let mut file = std::fs::File::create(file_path)
        .with_context(|| format!("Failed to create file: {}", file_path.display()))?;

    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read chunk from response")?;
        std::io::Write::write_all(&mut file, &chunk).context("Failed to write chunk to file")?;
    }

    Ok(())
}

pub async fn download_chunk_with_range(
    client: &Client,
    url: &str,
    start_byte: u64,
    end_byte: u64,
) -> Result<Vec<u8>> {
    const MAX_RETRIES: u32 = 3;
    let mut last_error = None;

    for attempt in 0..MAX_RETRIES {
        let response = client
            .get(url)
            .header("Range", format!("bytes={start_byte}-{end_byte}"))
            .header("Connection", "keep-alive")
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 206 => {
                let chunk_data = resp
                    .bytes()
                    .await
                    .context("Failed to read chunk data")?
                    .to_vec();

                let expected_size = (end_byte - start_byte + 1) as usize;
                if chunk_data.len() != expected_size {
                    anyhow::bail!(
                        "Chunk size mismatch: expected {}, got {}",
                        expected_size,
                        chunk_data.len()
                    );
                }

                return Ok(chunk_data);
            }
            Ok(resp) => {
                last_error = Some(anyhow::anyhow!(
                    "Chunk download failed with status: {}",
                    resp.status()
                ));
            }
            Err(e) => {
                last_error = Some(anyhow::anyhow!("Network error: {}", e));
            }
        }

        if attempt < MAX_RETRIES - 1 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100 << attempt)).await;
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Max retries exceeded")))
}

pub fn calculate_chunks(total_size: u64) -> Vec<(u64, u64)> {
    let optimal_chunk_size = calculate_optimal_chunk_size(total_size);

    let num_chunks = total_size.div_ceil(optimal_chunk_size);
    (0..num_chunks)
        .map(|chunk_idx| {
            let start_byte = chunk_idx * optimal_chunk_size;
            let end_byte = std::cmp::min(start_byte + optimal_chunk_size - 1, total_size - 1);
            (start_byte, end_byte)
        })
        .collect()
}

pub fn calculate_chunks_with_size(total_size: u64, chunk_size: u64) -> Vec<(u64, u64)> {
    let num_chunks = total_size.div_ceil(chunk_size);
    (0..num_chunks)
        .map(|chunk_idx| {
            let start_byte = chunk_idx * chunk_size;
            let end_byte = std::cmp::min(start_byte + chunk_size - 1, total_size - 1);
            (start_byte, end_byte)
        })
        .collect()
}

pub fn calculate_optimal_chunk_size(total_size: u64) -> u64 {
    if total_size < 100 * 1024 * 1024 {
        8 * 1024 * 1024
    } else if total_size < 1024 * 1024 * 1024 {
        32 * 1024 * 1024
    } else if total_size < 10 * 1024 * 1024 * 1024 {
        64 * 1024 * 1024
    } else {
        128 * 1024 * 1024
    }
}

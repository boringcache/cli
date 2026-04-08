use anyhow::{Context, Result};
use std::time::Duration;
use tokio::time::sleep;

const TRANSFER_RETRY_ATTEMPTS: u32 = 5;
const TRANSFER_RETRY_BASE_DELAY_MS: u64 = 1_000;
const TRANSFER_RETRY_MAX_DELAY_MS: u64 = 8_000;
const TRANSFER_RETRY_AFTER_MAX_SECS: u64 = 30;

fn transfer_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1);
    let backoff = TRANSFER_RETRY_BASE_DELAY_MS.saturating_mul(2_u64.pow(exponent));
    Duration::from_millis(backoff.min(TRANSFER_RETRY_MAX_DELAY_MS))
}

fn retry_after_delay_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if raw.is_empty() {
        return None;
    }
    let seconds = raw
        .parse::<u64>()
        .ok()?
        .clamp(1, TRANSFER_RETRY_AFTER_MAX_SECS);
    Some(Duration::from_secs(seconds))
}

fn is_retryable_transfer_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
}

fn is_retryable_transfer_error(err: &reqwest::Error) -> bool {
    if err.is_timeout() || err.is_connect() {
        return true;
    }

    match err.status() {
        Some(status) => is_retryable_transfer_status(status),
        None => false,
    }
}

pub(crate) async fn send_transfer_request_with_retry<F, Fut>(
    operation_name: &str,
    mut send_request: F,
) -> Result<reqwest::Response>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response>>,
{
    let mut attempt = 0u32;

    loop {
        attempt += 1;

        let response_result = send_request().await;
        match response_result {
            Ok(response) => {
                let status = response.status();
                if is_retryable_transfer_status(status) && attempt < TRANSFER_RETRY_ATTEMPTS {
                    let delay = retry_after_delay_from_headers(response.headers())
                        .unwrap_or_else(|| transfer_retry_delay(attempt));
                    sleep(delay).await;
                    continue;
                }
                return Ok(response);
            }
            Err(err) => {
                let retryable = err
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
                    .map(is_retryable_transfer_error)
                    .unwrap_or(false);

                if retryable && attempt < TRANSFER_RETRY_ATTEMPTS {
                    sleep(transfer_retry_delay(attempt)).await;
                    continue;
                }

                let context = if attempt > 1 {
                    format!("{} failed after {} attempts", operation_name, attempt)
                } else {
                    format!("{} failed", operation_name)
                };
                return Err(err).context(context);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_delay_uses_header_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "3".parse().unwrap());
        assert_eq!(
            retry_after_delay_from_headers(&headers),
            Some(Duration::from_secs(3))
        );
    }

    #[test]
    fn retry_after_delay_caps_large_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "120".parse().unwrap());
        assert_eq!(
            retry_after_delay_from_headers(&headers),
            Some(Duration::from_secs(TRANSFER_RETRY_AFTER_MAX_SECS))
        );
    }

    #[test]
    fn retry_after_delay_ignores_invalid_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "abc".parse().unwrap());
        assert_eq!(retry_after_delay_from_headers(&headers), None);
    }
}

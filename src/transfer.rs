use anyhow::{Context, Result};
use std::time::Duration;
use tokio::time::sleep;

const TRANSFER_RETRY_ATTEMPTS: u32 = 3;
const TRANSFER_RETRY_BASE_DELAY_MS: u64 = 500;
const TRANSFER_RETRY_MAX_DELAY_MS: u64 = 2_000;

fn transfer_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1);
    let backoff = TRANSFER_RETRY_BASE_DELAY_MS.saturating_mul(2_u64.pow(exponent));
    Duration::from_millis(backoff.min(TRANSFER_RETRY_MAX_DELAY_MS))
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

        match send_request().await {
            Ok(response) => {
                let status = response.status();
                if is_retryable_transfer_status(status) && attempt < TRANSFER_RETRY_ATTEMPTS {
                    sleep(transfer_retry_delay(attempt)).await;
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

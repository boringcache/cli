use anyhow::Error;
use std::time::Duration;

use crate::error::BoringCacheError;

pub(super) fn should_retry(error: &Error) -> bool {
    !error
        .downcast_ref::<BoringCacheError>()
        .is_some_and(|error| matches!(error, BoringCacheError::ConnectionError(_)))
        && !crate::error::is_non_retryable_error(error)
}

pub(super) fn backoff_delay(attempt: u32, max_backoff_secs: u64) -> Duration {
    let delay_secs = std::cmp::min(2_u64.pow(attempt - 1), max_backoff_secs);
    Duration::from_secs(delay_secs)
}

pub(super) fn exhausted_error(
    operation_name: &str,
    max_retries: u32,
    error: Error,
) -> anyhow::Error {
    anyhow::anyhow!(
        "{} failed after {} attempts: {}",
        operation_name,
        max_retries,
        error
    )
}

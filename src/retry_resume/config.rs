use anyhow::Result;
use tokio::time::sleep;

use crate::ui;

use super::policy::{backoff_delay, exhausted_error, should_retry};
use super::{MAX_BACKOFF_SECS, MAX_RETRIES};

pub struct RetryConfig {
    pub max_retries: u32,
    pub max_backoff_secs: u64,
    pub verbose: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: MAX_RETRIES,
            max_backoff_secs: MAX_BACKOFF_SECS,
            verbose: false,
        }
    }
}

impl RetryConfig {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            ..Default::default()
        }
    }

    pub async fn retry_with_backoff<T, F, Fut>(
        &self,
        operation_name: &str,
        mut operation: F,
    ) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempts = 0;

        loop {
            attempts += 1;

            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if !should_retry(&err) {
                        return Err(err);
                    }

                    if attempts >= self.max_retries {
                        return Err(exhausted_error(operation_name, self.max_retries, err));
                    }

                    if self.verbose {
                        ui::info(&format!(
                            "{} failed, retrying... ({}/{}): {}",
                            operation_name, attempts, self.max_retries, err
                        ));
                    }

                    sleep(backoff_delay(attempts, self.max_backoff_secs)).await;
                }
            }
        }
    }
}

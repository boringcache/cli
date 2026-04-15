use crate::error::BoringCacheError;
use crate::ui;
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

pub const MAX_RETRIES: u32 = 3;
pub const MAX_BACKOFF_SECS: u64 = 8;

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

            let operation_result = operation().await;
            match operation_result {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if e.downcast_ref::<BoringCacheError>()
                        .is_some_and(|error| matches!(error, BoringCacheError::ConnectionError(_)))
                        || crate::error::is_non_retryable_error(&e)
                    {
                        return Err(e);
                    }

                    if attempts < self.max_retries {
                        if self.verbose {
                            ui::info(&format!(
                                "{} failed, retrying... ({}/{}): {}",
                                operation_name, attempts, self.max_retries, e
                            ));
                        }
                        let delay = std::cmp::min(2_u64.pow(attempts - 1), self.max_backoff_secs);
                        sleep(Duration::from_secs(delay)).await;
                        continue;
                    } else {
                        return Err(anyhow::anyhow!(
                            "{} failed after {} attempts: {}",
                            operation_name,
                            self.max_retries,
                            e
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, MAX_RETRIES);
        assert_eq!(config.max_backoff_secs, MAX_BACKOFF_SECS);
        assert!(!config.verbose);
    }

    #[test]
    fn test_retry_config_new() {
        let config = RetryConfig::new(true);
        assert_eq!(config.max_retries, MAX_RETRIES);
        assert_eq!(config.max_backoff_secs, MAX_BACKOFF_SECS);
        assert!(config.verbose);
    }

    #[tokio::test]
    async fn test_retry_success_immediate() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<i32, anyhow::Error>(42)
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    let current_count = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if current_count < 3 {
                        Err(anyhow::anyhow!("Temporary failure"))
                    } else {
                        Ok::<i32, anyhow::Error>(42)
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_max_retries_reached() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let start_time = Instant::now();
        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err::<i32, anyhow::Error>(anyhow::anyhow!("Always fails"))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(start_time.elapsed() >= Duration::from_secs(1));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed after 3 attempts")
        );
    }

    #[tokio::test]
    async fn test_retry_retries_timeout_errors() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    let current_count = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if current_count < 3 {
                        Err::<i32, anyhow::Error>(anyhow::anyhow!(
                            "Request timeout: error sending request for url"
                        ))
                    } else {
                        Ok::<i32, anyhow::Error>(42)
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
}

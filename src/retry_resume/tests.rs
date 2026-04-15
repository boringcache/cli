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
    assert!(start_time.elapsed() >= std::time::Duration::from_secs(1));
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

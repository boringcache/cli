use super::render::format_number;
use super::*;
use std::time::Duration;

#[test]
fn test_format_number() {
    assert_eq!(format_number(500), "500");
    assert_eq!(format_number(1500), "1.5K");
    assert_eq!(format_number(1500000), "1.5M");
}

#[tokio::test]
async fn test_progress_system() {
    let system = System::new();
    let reporter = system.reporter();

    reporter
        .session_start("test".to_string(), "Test Operation".to_string(), 2)
        .unwrap();
    reporter
        .step_start("test".to_string(), 1, "Step 1".to_string(), None)
        .unwrap();
    reporter
        .step_complete("test".to_string(), 1, Duration::from_millis(100))
        .unwrap();

    let summary = Summary {
        size_bytes: 1024,
        file_count: 5,
        digest: Some("abcd1234".to_string()),
        path: Some("/tmp/test".to_string()),
    };

    reporter
        .session_complete("test".to_string(), Duration::from_secs(1), summary)
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    drop(reporter);
    system.shutdown().unwrap();
}

use super::*;

#[test]
fn test_error_display_messages() {
    assert!(
        BoringCacheError::ConfigNotFound
            .to_string()
            .contains("Config file not found")
    );
    assert!(
        BoringCacheError::TokenNotFound
            .to_string()
            .contains("API token not found")
    );
    assert!(BoringCacheError::CacheMiss.to_string().contains("miss"));
    assert!(
        BoringCacheError::cache_pending()
            .to_string()
            .contains("in progress")
    );
}

#[test]
fn test_error_with_context() {
    let api_err = BoringCacheError::ApiError("test error".to_string());
    assert!(api_err.to_string().contains("test error"));

    let ws_err = BoringCacheError::WorkspaceNotFound("my-workspace".to_string());
    assert!(ws_err.to_string().contains("my-workspace"));

    let conflict_err = BoringCacheError::cache_conflict("tag already claimed");
    assert!(conflict_err.to_string().contains("tag already claimed"));

    let auth_err = BoringCacheError::AuthenticationFailed("invalid token".to_string());
    assert!(auth_err.to_string().contains("invalid token"));

    let request_config_err = BoringCacheError::RequestConfiguration("invalid request".to_string());
    assert!(request_config_err.to_string().contains("invalid request"));
}

#[test]
fn test_io_error_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let boring_err: BoringCacheError = io_err.into();
    assert!(matches!(boring_err, BoringCacheError::IoError(_)));
}

#[test]
fn test_json_error_conversion() {
    let json_err = serde_json::from_str::<String>("invalid json").unwrap_err();
    let boring_err: BoringCacheError = json_err.into();
    assert!(matches!(boring_err, BoringCacheError::ApiError(_)));
}

#[test]
fn test_non_retryable_error_detection() {
    let err: anyhow::Error =
        BoringCacheError::RequestConfiguration("bad header".to_string()).into();
    assert!(is_non_retryable_error(&err));
    assert!(!is_connection_error(&err));
}

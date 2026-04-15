use crate::error::BoringCacheError;

pub fn is_connection_error(err: &anyhow::Error) -> bool {
    if let Some(bc_error) = err.downcast_ref::<BoringCacheError>() {
        return matches!(bc_error, BoringCacheError::ConnectionError(_));
    }

    let err_str = err.to_string().to_lowercase();
    err_str.contains("cannot connect")
        || err_str.contains("connection refused")
        || err_str.contains("timed out")
        || err_str.contains("timeout")
        || err_str.contains("authentication failed")
}

pub fn is_non_retryable_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<BoringCacheError>()
        .is_some_and(|bc_error| matches!(bc_error, BoringCacheError::RequestConfiguration(_)))
}

use super::*;

#[derive(Debug)]
pub(crate) enum FlushError {
    Conflict(String),
    Transient(String),
    Permanent(String),
}

pub(crate) fn classify_flush_error(error: &anyhow::Error, context: &str) -> FlushError {
    let message = format!("{context}: {error}");
    let lower = message.to_ascii_lowercase();

    if let Some(bc_error) = error.downcast_ref::<BoringCacheError>() {
        match bc_error {
            BoringCacheError::CacheConflict { .. } => {
                return FlushError::Conflict(message);
            }
            BoringCacheError::CachePending => {
                if context.contains("confirm") {
                    return FlushError::Transient(message);
                }
                return FlushError::Conflict(message);
            }
            BoringCacheError::NetworkError(_) | BoringCacheError::ConnectionError(_) => {
                return FlushError::Transient(message);
            }
            BoringCacheError::ConfigNotFound
            | BoringCacheError::TokenNotFound
            | BoringCacheError::RequestConfiguration(_)
            | BoringCacheError::WorkspaceNotFound(_)
            | BoringCacheError::AuthenticationFailed(_) => {
                return FlushError::Permanent(message);
            }
            _ => {}
        }
    }

    let is_conflict = lower.contains("another cache upload is in progress");
    let conflict_status = has_status_code(&lower, 409)
        || has_status_code(&lower, 412)
        || has_status_code(&lower, 423);
    let conflict_hint = lower.contains("precondition failed")
        || lower.contains("etag mismatch")
        || lower.contains("manifest digest mismatch");
    if is_conflict || conflict_status || conflict_hint {
        return FlushError::Conflict(message);
    }

    let storage_verification_pending = lower.contains("not yet verified in storage")
        || lower.contains("retry after upload completes");
    if storage_verification_pending {
        return FlushError::Permanent(message);
    }

    let upload_receipts_pending = context.contains("confirm")
        && (lower.contains("upload_session_receipts_incomplete")
            || lower.contains("requires complete upload receipts"));
    if upload_receipts_pending {
        return FlushError::Transient(message);
    }

    let transient_status = has_status_code(&lower, 429)
        || has_status_code(&lower, 500)
        || has_status_code(&lower, 502)
        || has_status_code(&lower, 503)
        || has_status_code(&lower, 504);
    let transient_hint = lower.contains("transient error")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("deadline has elapsed")
        || lower.contains("connect error")
        || lower.contains("temporarily unavailable")
        || lower.contains("rate limit exceeded")
        || lower.contains("cannot connect")
        || lower.contains("connection refused")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
        || lower.contains("unexpected eof")
        || lower.contains("unexpected-eof")
        || lower.contains("close_notify");
    if transient_status || transient_hint {
        return FlushError::Transient(message);
    }

    if edge_blob_url_planning_bad_request(&lower) {
        return FlushError::Transient(message);
    }

    let permanent_status = has_status_code(&lower, 400)
        || has_status_code(&lower, 401)
        || has_status_code(&lower, 403)
        || has_status_code(&lower, 404)
        || has_status_code(&lower, 405)
        || has_status_code(&lower, 410)
        || has_status_code(&lower, 411)
        || has_status_code(&lower, 413)
        || has_status_code(&lower, 414)
        || has_status_code(&lower, 415)
        || has_status_code(&lower, 422);
    let permanent_hint = lower.contains("authentication failed")
        || lower.contains("invalid or expired token")
        || lower.contains("access forbidden")
        || lower.contains("workspace not found")
        || lower.contains("cache_entry must be pending or ready")
        || lower.contains("unprocessable");
    if permanent_status || permanent_hint {
        return FlushError::Permanent(message);
    }

    FlushError::Transient(message)
}

fn edge_blob_url_planning_bad_request(lower: &str) -> bool {
    has_status_code(lower, 400)
        && (lower.contains("/caches/blobs/stage") || lower.contains("/caches/blobs/download-urls"))
        && (lower.contains("<html")
            || lower.contains("<title>400 bad request</title>")
            || lower.contains("nginx"))
}

pub(crate) fn has_status_code(lower: &str, code: u16) -> bool {
    let code = code.to_string();
    lower.contains(&format!("http {code}"))
        || lower.contains(&format!("status {code}"))
        || lower.contains(&format!("returned {code}"))
        || lower.contains(&format!("({code})"))
}

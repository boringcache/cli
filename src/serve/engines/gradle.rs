use axum::http::StatusCode;

use crate::serve::cache_registry::KvPutOptions;

pub(crate) fn gradle_put_options() -> KvPutOptions {
    KvPutOptions::default().with_spool_reject_status(StatusCode::PAYLOAD_TOO_LARGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gradle_put_rejects_oversized_payloads_with_gradle_nonfatal_status() {
        let options = gradle_put_options();
        assert_eq!(options.spool_reject_status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}

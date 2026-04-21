use axum::http::StatusCode;

use crate::serve::cache_registry::KvPutOptions;

pub(crate) fn nx_artifact_put_options() -> KvPutOptions {
    KvPutOptions::default().with_existing_reject_status(StatusCode::CONFLICT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nx_artifact_put_rejects_existing_records_with_conflict() {
        let options = nx_artifact_put_options();
        assert_eq!(options.existing_reject_status(), Some(StatusCode::CONFLICT));
    }
}

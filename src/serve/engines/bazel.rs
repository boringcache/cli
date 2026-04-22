use axum::body::Body;
use axum::http::{Method, StatusCode};
use axum::response::Response;

use crate::serve::cache_registry::{KvBlobIntegrity, KvNamespace};
use crate::serve::cache_registry::{
    RegistryError, get_or_head_kv_object_with_integrity, put_kv_object_with_integrity,
};
use crate::serve::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BazelStore {
    ActionCache,
    ContentAddressableStore,
}

impl BazelStore {
    pub(crate) fn namespace(self) -> KvNamespace {
        match self {
            Self::ActionCache => KvNamespace::BazelAc,
            Self::ContentAddressableStore => KvNamespace::BazelCas,
        }
    }

    pub(crate) fn blob_integrity(self) -> Option<KvBlobIntegrity> {
        match self {
            Self::ActionCache => None,
            Self::ContentAddressableStore => {
                Some(KvBlobIntegrity::new("Bazel CAS", expected_cas_blob_digest))
            }
        }
    }
}

fn expected_cas_blob_digest(key: &str) -> String {
    format!("sha256:{}", key.to_ascii_lowercase())
}

async fn handle_store(
    state: &AppState,
    store: BazelStore,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    let namespace = store.namespace();
    let integrity = store.blob_integrity();
    match method {
        Method::PUT => {
            put_kv_object_with_integrity(
                state,
                namespace,
                digest_hex,
                body,
                StatusCode::OK,
                integrity,
            )
            .await
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object_with_integrity(
                state,
                namespace,
                digest_hex,
                method == Method::HEAD,
                integrity,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Bazel cache supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_ac(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    handle_store(state, BazelStore::ActionCache, method, digest_hex, body).await
}

pub(crate) async fn handle_cas(
    state: &AppState,
    method: Method,
    digest_hex: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    handle_store(
        state,
        BazelStore::ContentAddressableStore,
        method,
        digest_hex,
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bazel_store_maps_to_distinct_kv_namespaces() {
        assert!(matches!(
            BazelStore::ActionCache.namespace(),
            KvNamespace::BazelAc
        ));
        assert!(matches!(
            BazelStore::ContentAddressableStore.namespace(),
            KvNamespace::BazelCas
        ));
    }

    #[test]
    fn cas_integrity_expects_digest_from_lowercase_key() {
        let integrity = BazelStore::ContentAddressableStore
            .blob_integrity()
            .expect("CAS integrity policy");
        assert_eq!(
            integrity.expected_digest("ABCDEF"),
            "sha256:abcdef".to_string()
        );
        assert!(BazelStore::ActionCache.blob_integrity().is_none());
    }
}

use crate::serve::cache_registry::{KvBlobIntegrity, KvNamespace};

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

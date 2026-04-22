use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobReadSource {
    LocalCache,
    RemoteFetch,
}

impl BlobReadSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::LocalCache => "local_cache",
            Self::RemoteFetch => "remote_fetch",
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct StartupPrefetchCandidates {
    pub(super) ordered_blobs: Vec<BlobDescriptor>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DownloadUrlPreloadStats {
    pub(super) requested: usize,
    pub(super) resolved: usize,
    pub(super) missing: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct StartupPrefetchTarget {
    pub(super) blob: BlobDescriptor,
    pub(super) cached_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StartupPrefetchTargetSummary {
    pub(super) cached_url_count: usize,
    pub(super) unresolved_url_count: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KvNamespace {
    BazelAc,
    BazelCas,
    Gradle,
    Maven,
    Nx,
    NxTerminalOutput,
    Turborepo,
    TurborepoMeta,
    Sccache,
    GoCache,
}

impl KvNamespace {
    pub(crate) fn normalize_key(self, key: &str) -> String {
        match self {
            KvNamespace::BazelAc
            | KvNamespace::BazelCas
            | KvNamespace::Gradle
            | KvNamespace::GoCache => key.to_ascii_lowercase(),
            KvNamespace::Maven
            | KvNamespace::Nx
            | KvNamespace::NxTerminalOutput
            | KvNamespace::Turborepo
            | KvNamespace::TurborepoMeta
            | KvNamespace::Sccache => key.to_string(),
        }
    }

    fn namespace_prefix(self) -> &'static str {
        match self {
            KvNamespace::BazelAc => "bazel_ac",
            KvNamespace::BazelCas => "bazel_cas",
            KvNamespace::Gradle => "gradle",
            KvNamespace::Maven => "maven",
            KvNamespace::Nx => "nx",
            KvNamespace::NxTerminalOutput => "nx_terminal",
            KvNamespace::Turborepo => "turbo",
            KvNamespace::TurborepoMeta => "turbo_meta",
            KvNamespace::Sccache => "sccache",
            KvNamespace::GoCache => "go_cache",
        }
    }

    pub(crate) fn scoped_key(self, key: &str) -> String {
        format!("{}/{}", self.namespace_prefix(), self.normalize_key(key))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct KvBlobIntegrity {
    label: &'static str,
    expected_digest_for_key: fn(&str) -> String,
}

impl KvBlobIntegrity {
    pub(crate) fn new(label: &'static str, expected_digest_for_key: fn(&str) -> String) -> Self {
        Self {
            label,
            expected_digest_for_key,
        }
    }

    pub(crate) fn expected_digest(self, key: &str) -> String {
        (self.expected_digest_for_key)(key)
    }

    pub(super) fn blob_matches_key(self, key: &str, blob: &BlobDescriptor) -> bool {
        blob.digest.eq_ignore_ascii_case(&self.expected_digest(key))
    }

    pub(super) fn validate_put_digest(
        self,
        key: &str,
        blob_digest: &str,
    ) -> Result<(), RegistryError> {
        let expected_digest = self.expected_digest(key);
        if !blob_digest.eq_ignore_ascii_case(&expected_digest) {
            return Err(RegistryError::new(
                StatusCode::BAD_REQUEST,
                format!(
                    "{} digest mismatch: expected {expected_digest}, got {blob_digest}",
                    self.label
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn log_mismatch(self, phase: &str, key: &str, blob: &BlobDescriptor) {
        log::warn!(
            "{} {} blob digest mismatch: key={} digest={}",
            self.label,
            phase,
            key,
            blob.digest
        );
    }
}

#[derive(Clone, Copy)]
pub(crate) struct KvPutOptions {
    pub(super) integrity: Option<KvBlobIntegrity>,
    pub(super) spool_reject_status: StatusCode,
    pub(super) existing_reject_status: Option<StatusCode>,
}

impl Default for KvPutOptions {
    fn default() -> Self {
        Self {
            integrity: None,
            spool_reject_status: StatusCode::SERVICE_UNAVAILABLE,
            existing_reject_status: None,
        }
    }
}

impl KvPutOptions {
    pub(crate) fn with_integrity(mut self, integrity: Option<KvBlobIntegrity>) -> Self {
        self.integrity = integrity;
        self
    }

    pub(crate) fn with_spool_reject_status(mut self, status: StatusCode) -> Self {
        self.spool_reject_status = status;
        self
    }

    pub(crate) fn with_existing_reject_status(mut self, status: StatusCode) -> Self {
        self.existing_reject_status = Some(status);
        self
    }

    #[cfg(test)]
    pub(crate) fn spool_reject_status(&self) -> StatusCode {
        self.spool_reject_status
    }

    #[cfg(test)]
    pub(crate) fn existing_reject_status(&self) -> Option<StatusCode> {
        self.existing_reject_status
    }
}

use std::future::Future;

pub const CONTENT_ADDRESSED_ENCRYPTION_FALLBACK_WARNING: &str =
    "Detected content-addressed layout but encryption is enabled; using archive transport";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasAdapterKind {
    Oci,
    File,
}

impl CasAdapterKind {
    pub fn accepts_server_kind(self, server_kind: crate::cache_adapter::CacheAdapterKind) -> bool {
        match self {
            CasAdapterKind::Oci => matches!(
                server_kind,
                crate::cache_adapter::CacheAdapterKind::Cas
                    | crate::cache_adapter::CacheAdapterKind::CasOci
            ),
            CasAdapterKind::File => matches!(
                server_kind,
                crate::cache_adapter::CacheAdapterKind::Cas
                    | crate::cache_adapter::CacheAdapterKind::CasBazel
            ),
        }
    }

    pub fn cas_layout(self, detected_kind: crate::cache_adapter::CacheAdapterKind) -> &'static str {
        match self {
            CasAdapterKind::Oci => "oci-v1",
            CasAdapterKind::File => match detected_kind {
                crate::cache_adapter::CacheAdapterKind::CasBazel => "bazel-v2",
                _ => "file-v1",
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterDispatchKind {
    Archive,
    Oci,
    File,
}

impl AdapterDispatchKind {
    pub fn transport_kind(&self) -> crate::cache_adapter::CacheAdapterKind {
        match self {
            AdapterDispatchKind::Archive => crate::cache_adapter::CacheAdapterKind::Archive,
            AdapterDispatchKind::Oci => crate::cache_adapter::CacheAdapterKind::CasOci,
            AdapterDispatchKind::File => crate::cache_adapter::CacheAdapterKind::Cas,
        }
    }

    pub fn cas(self) -> Option<CasAdapterKind> {
        match self {
            AdapterDispatchKind::Archive => None,
            AdapterDispatchKind::Oci => Some(CasAdapterKind::Oci),
            AdapterDispatchKind::File => Some(CasAdapterKind::File),
        }
    }

    pub fn accepts_server_kind(self, server_kind: crate::cache_adapter::CacheAdapterKind) -> bool {
        match self.cas() {
            Some(cas_adapter) => cas_adapter.accepts_server_kind(server_kind),
            None => server_kind == crate::cache_adapter::CacheAdapterKind::Archive,
        }
    }

    pub fn cas_layout(
        self,
        detected_kind: crate::cache_adapter::CacheAdapterKind,
    ) -> Option<&'static str> {
        self.cas()
            .map(|cas_adapter| cas_adapter.cas_layout(detected_kind))
    }

    pub async fn dispatch<T, ArchiveFn, OciFn, FileFn, ArchiveFuture, OciFuture, FileFuture>(
        self,
        archive: ArchiveFn,
        oci: OciFn,
        file: FileFn,
    ) -> T
    where
        ArchiveFn: FnOnce() -> ArchiveFuture,
        OciFn: FnOnce() -> OciFuture,
        FileFn: FnOnce() -> FileFuture,
        ArchiveFuture: Future<Output = T>,
        OciFuture: Future<Output = T>,
        FileFuture: Future<Output = T>,
    {
        match self {
            AdapterDispatchKind::Archive => archive().await,
            AdapterDispatchKind::Oci => oci().await,
            AdapterDispatchKind::File => file().await,
        }
    }
}

pub fn select_transport_adapter(
    kind: crate::cache_adapter::CacheAdapterKind,
) -> AdapterDispatchKind {
    match kind {
        crate::cache_adapter::CacheAdapterKind::Archive => AdapterDispatchKind::Archive,
        crate::cache_adapter::CacheAdapterKind::CasOci => AdapterDispatchKind::Oci,
        crate::cache_adapter::CacheAdapterKind::Cas
        | crate::cache_adapter::CacheAdapterKind::CasBazel => AdapterDispatchKind::File,
    }
}

pub fn select_layout_adapter(
    kind: crate::cache_adapter::CacheAdapterKind,
    encrypt: bool,
) -> LayoutAdapterSelection {
    match kind {
        crate::cache_adapter::CacheAdapterKind::Archive => LayoutAdapterSelection {
            adapter: AdapterDispatchKind::Archive,
            used_encryption_fallback: false,
        },
        crate::cache_adapter::CacheAdapterKind::CasOci => {
            if encrypt {
                LayoutAdapterSelection {
                    adapter: AdapterDispatchKind::Archive,
                    used_encryption_fallback: true,
                }
            } else {
                LayoutAdapterSelection {
                    adapter: AdapterDispatchKind::Oci,
                    used_encryption_fallback: false,
                }
            }
        }
        crate::cache_adapter::CacheAdapterKind::Cas
        | crate::cache_adapter::CacheAdapterKind::CasBazel => {
            if encrypt {
                LayoutAdapterSelection {
                    adapter: AdapterDispatchKind::Archive,
                    used_encryption_fallback: true,
                }
            } else {
                LayoutAdapterSelection {
                    adapter: AdapterDispatchKind::File,
                    used_encryption_fallback: false,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutAdapterSelection {
    pub adapter: AdapterDispatchKind,
    pub used_encryption_fallback: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_adapter_uses_bazel_layout_when_detected() {
        assert_eq!(
            AdapterDispatchKind::File.cas_layout(crate::cache_adapter::CacheAdapterKind::CasBazel),
            Some("bazel-v2")
        );
        assert_eq!(
            AdapterDispatchKind::File.cas_layout(crate::cache_adapter::CacheAdapterKind::Cas),
            Some("file-v1")
        );
    }

    #[test]
    fn oci_adapter_accepts_generic_cas_server_mode() {
        assert!(AdapterDispatchKind::Oci
            .accepts_server_kind(crate::cache_adapter::CacheAdapterKind::Cas));
        assert!(AdapterDispatchKind::Oci
            .accepts_server_kind(crate::cache_adapter::CacheAdapterKind::CasOci));
        assert!(!AdapterDispatchKind::Oci
            .accepts_server_kind(crate::cache_adapter::CacheAdapterKind::CasBazel));
    }

    #[test]
    fn encrypted_content_addressed_layouts_fall_back_to_archive() {
        let selection = select_layout_adapter(crate::cache_adapter::CacheAdapterKind::CasOci, true);
        assert_eq!(selection.adapter, AdapterDispatchKind::Archive);
        assert!(selection.used_encryption_fallback);
    }
}

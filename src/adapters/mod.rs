use anyhow::Result;

pub const CONTENT_ADDRESSED_ENCRYPTION_FALLBACK_WARNING: &str =
    "Detected content-addressed layout but encryption is enabled; using archive transport";

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
}

pub fn select_transport_adapter(
    kind: crate::cache_adapter::CacheAdapterKind,
) -> Result<AdapterDispatchKind> {
    let adapter = match kind {
        crate::cache_adapter::CacheAdapterKind::Archive => AdapterDispatchKind::Archive,
        crate::cache_adapter::CacheAdapterKind::CasOci => AdapterDispatchKind::Oci,
        crate::cache_adapter::CacheAdapterKind::Cas
        | crate::cache_adapter::CacheAdapterKind::CasBazel => AdapterDispatchKind::File,
    };
    Ok(adapter)
}

pub fn select_layout_adapter(
    kind: crate::cache_adapter::CacheAdapterKind,
    encrypt: bool,
) -> Result<LayoutAdapterSelection> {
    let selection = match kind {
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
    };
    Ok(selection)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutAdapterSelection {
    pub adapter: AdapterDispatchKind,
    pub used_encryption_fallback: bool,
}

pub fn cas_layout_for(
    detected_kind: crate::cache_adapter::CacheAdapterKind,
    adapter: AdapterDispatchKind,
) -> Option<&'static str> {
    match adapter {
        AdapterDispatchKind::Archive => None,
        AdapterDispatchKind::Oci => Some("oci-v1"),
        AdapterDispatchKind::File => match detected_kind {
            crate::cache_adapter::CacheAdapterKind::CasBazel => Some("bazel-v2"),
            _ => Some("file-v1"),
        },
    }
}

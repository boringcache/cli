pub(crate) mod blob_download_urls;
pub mod cache_registry;
pub mod cas_publish;
pub(crate) mod engines;
pub mod http;
mod runtime;
pub mod state;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OciHydrationPolicy {
    #[default]
    MetadataOnly,
    BodiesBeforeReady,
    BodiesBackground,
}

impl OciHydrationPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata-only",
            Self::BodiesBeforeReady => "bodies-before-ready",
            Self::BodiesBackground => "bodies-background",
        }
    }

    pub fn waits_before_ready(self) -> bool {
        matches!(self, Self::BodiesBeforeReady)
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim() {
            "metadata-only" => Ok(Self::MetadataOnly),
            "bodies-before-ready" => Ok(Self::BodiesBeforeReady),
            "bodies-background" => Ok(Self::BodiesBackground),
            other => anyhow::bail!(
                "Invalid OCI hydration policy '{other}'. Expected metadata-only, bodies-before-ready, or bodies-background."
            ),
        }
    }
}

pub use http::error;
pub use http::handlers;
pub use http::routes;
pub use runtime::{ServeHandle, run_server, start_server_background};

use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct CacheRegistryArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: String,

    #[arg(
        help = "Comma-separated cache tags. All are human-facing OCI aliases; the first is the primary display tag"
    )]
    pub tag: String,

    #[arg(short, long, default_value = "5000")]
    pub port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(long, help = "Disable automatic platform suffix for cache tags")]
    pub no_platform: bool,

    #[arg(long, help = "Disable automatic git suffix for cache tags")]
    pub no_git: bool,

    #[arg(
        long,
        value_name = "KEY=VALUE",
        help = "Attach low-cardinality metadata hints to proxy sessions (repeatable; also reads BORINGCACHE_PROXY_METADATA_HINTS)"
    )]
    pub metadata_hint: Vec<String>,

    #[arg(
        long,
        value_name = "NAME@REFERENCE",
        help = "Seed OCI manifest cache for selected repository refs on startup (repeatable)"
    )]
    pub oci_prefetch_ref: Vec<String>,

    #[arg(
        long,
        default_value = "metadata-only",
        value_parser = ["metadata-only", "bodies-before-ready", "bodies-background"],
        help = "OCI/Docker startup hydration policy for selected refs"
    )]
    pub oci_hydration: String,

    #[arg(long, help = "Skip startup warming and serve cache reads on demand")]
    pub on_demand: bool,

    #[arg(
        long,
        hide = true,
        value_name = "PATH",
        help = "Internal: write a marker file when startup readiness is reached"
    )]
    pub ready_file: Option<String>,

    #[arg(
        long,
        help = "Return strict backend/cache errors instead of best-effort cache responses"
    )]
    pub fail_on_cache_error: bool,

    #[arg(
        long,
        help = "Serve cache reads only and treat proxy writes as successful no-ops"
    )]
    pub read_only: bool,
}

#[derive(Debug, Clone, Args)]
pub struct GoCacheProgArgs {
    #[arg(
        long,
        env = "BORINGCACHE_GOCACHEPROG_ENDPOINT",
        help = "Cache-registry base URL (example: http://127.0.0.1:5000)"
    )]
    pub endpoint: String,

    #[arg(
        long,
        env = "BORINGCACHE_GOCACHEPROG_TOKEN",
        help = "Optional bearer token for cache-registry requests"
    )]
    pub token: Option<String>,
}

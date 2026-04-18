#[derive(Debug, Clone, clap::Args)]
pub struct AdapterArgs {
    #[arg(long, help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(long, help = "Proxy cache tag")]
    pub tag: Option<String>,

    #[arg(short, long, help = "Port to bind and advertise (default: 5000)")]
    pub port: Option<u16>,

    #[arg(long, help = "Bind host for the local proxy (default: 127.0.0.1)")]
    pub host: Option<String>,

    #[arg(
        long = "endpoint-host",
        help = "Advertised host for wrapped clients when it differs from --host"
    )]
    pub endpoint_host: Option<String>,

    #[arg(long, help = "Disable automatic platform suffix for cache tags")]
    pub no_platform: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback restore logic"
    )]
    pub no_git: bool,

    #[arg(long, help = "Run proxy reads only and skip cache writes")]
    pub read_only: bool,

    #[arg(
        long,
        help = "Exit with error if cache operations encounter backend failures"
    )]
    pub fail_on_cache_error: bool,

    #[arg(
        long,
        value_name = "KEY=VALUE",
        help = "Attach low-cardinality metadata hints to proxy sessions (repeatable)"
    )]
    pub metadata_hint: Vec<String>,

    #[arg(
        long,
        value_name = "NAME@REFERENCE",
        help = "Resolve selected OCI repository refs during warm proxy startup (repeatable)"
    )]
    pub oci_prefetch_ref: Vec<String>,

    #[arg(long, help = "Skip startup warming and serve cache reads on demand")]
    pub on_demand: bool,

    #[arg(
        long,
        value_name = "ENTRY",
        value_delimiter = ',',
        help = "Project or built-in cache entry/entries to resolve (repeatable)"
    )]
    pub entry: Vec<String>,

    #[arg(
        long,
        value_name = "PROFILE",
        value_delimiter = ',',
        help = "Project cache profile(s) from .boringcache.toml (repeatable)"
    )]
    pub profile: Vec<String>,

    #[arg(long, help = "Skip restore phase for archive entries")]
    pub skip_restore: bool,

    #[arg(long, help = "Skip save phase for archive entries")]
    pub skip_save: bool,

    #[arg(long, help = "Run save phase even if command exits non-zero")]
    pub save_on_failure: bool,

    #[arg(long, help = "Docker cache export mode (default: max)")]
    pub cache_mode: Option<String>,

    #[arg(long, help = "Docker registry cache tag (default: buildcache)")]
    pub cache_ref_tag: Option<String>,

    #[arg(long, help = "Print the resolved execution plan without running")]
    pub dry_run: bool,

    #[arg(
        short,
        long,
        requires = "dry_run",
        help = "Print machine-readable dry-run output"
    )]
    pub json: bool,

    #[arg(
        last = true,
        help = "Command to execute (after --); if omitted, use [adapters.<tool>].command from .boringcache.toml. Proxy-backed args may use {PORT}, {ENDPOINT}, and {CACHE_REF}"
    )]
    pub command: Vec<String>,
}

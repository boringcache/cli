use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct MountArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: String,

    #[arg(help = "tag:path pair for the mount")]
    pub tag_path: String,

    #[arg(long, help = "Disable automatic platform suffix for tags")]
    pub no_platform: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback restore logic"
    )]
    pub no_git: bool,

    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,

    #[arg(
        long,
        help = "Allow clearing root, home, or current directory for restores"
    )]
    pub force: bool,

    #[arg(long, help = "Age recipient public key for encryption (age1...)")]
    pub recipient: Option<String>,

    #[arg(long, help = "Path to Age identity file for decryption")]
    pub identity: Option<String>,

    #[arg(
        long,
        help = "Require signed cache hits and fail if a returned server signature cannot be verified"
    )]
    pub require_server_signature: bool,
}

#[derive(Debug, Clone, Args)]
pub struct SaveArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: String,

    #[arg(help = "One or more tag:path pairs (comma-separated)")]
    pub path_tag_pairs: String,

    #[arg(long, help = "Disable automatic platform suffix for tags")]
    pub no_platform: bool,

    #[arg(long, help = "Force save even if cache entry already exists on server")]
    pub force: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback restore logic"
    )]
    pub no_git: bool,

    #[arg(
        long,
        help = "Exclude files matching patterns (comma-separated, can be repeated)",
        value_delimiter = ','
    )]
    pub exclude: Vec<String>,

    #[arg(long, help = "Age recipient public key for encryption (age1...)")]
    pub recipient: Option<String>,

    #[arg(
        long,
        help = "Exit with error if save encounters cache/backend failures"
    )]
    pub fail_on_cache_error: bool,
}

#[derive(Debug, Clone, Args)]
pub struct RestoreArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: String,

    #[arg(help = "One or more tag:path pairs (comma-separated)")]
    pub tag_path_pairs: String,

    #[arg(long, help = "Disable automatic platform suffix for tags")]
    pub no_platform: bool,

    #[arg(long, help = "Exit with error if cache entry is not found")]
    pub fail_on_cache_miss: bool,

    #[arg(long, help = "Check if a cache entry exists without downloading")]
    pub lookup_only: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback restore logic"
    )]
    pub no_git: bool,

    #[arg(long, help = "Path to Age identity file for decryption")]
    pub identity: Option<String>,

    #[arg(
        long,
        help = "Allow restoring symlinks that point outside the restore root; disabled by default for security"
    )]
    pub allow_external_symlinks: bool,

    #[arg(
        long,
        help = "Exit with error if restore encounters cache/backend failures"
    )]
    pub fail_on_cache_error: bool,
}

#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    #[arg(
        value_name = "WORKSPACE_OR_TAG_PATHS",
        help = "Workspace name, or manual tag:path pairs when omitting WORKSPACE"
    )]
    pub workspace_or_tag_path: Option<String>,

    #[arg(help = "Manual tag:path pairs (comma-separated)")]
    pub tag_path_pairs: Option<String>,

    #[arg(
        long,
        value_name = "PROFILE",
        value_delimiter = ',',
        help = "Project cache profile(s) from .boringcache.toml (repeatable)"
    )]
    pub profile: Vec<String>,

    #[arg(
        long,
        value_name = "ENTRY",
        value_delimiter = ',',
        help = "Project or built-in cache entry/entries to resolve (repeatable)"
    )]
    pub entry: Vec<String>,

    #[arg(
        long = "archive-path",
        hide = true,
        value_name = "PATH",
        help = "Internal integration flag: plan a path-derived archive entry (repeatable)"
    )]
    pub archive_path: Vec<String>,

    #[arg(
        long = "archive-tag-prefix",
        hide = true,
        value_name = "PREFIX",
        help = "Internal integration flag: primary prefix for path-derived archive tags"
    )]
    pub archive_tag_prefix: Option<String>,

    #[arg(
        long = "archive-restore-prefix",
        hide = true,
        value_name = "PREFIX",
        value_delimiter = ',',
        help = "Internal integration flag: fallback prefix for path-derived archive tags (repeatable)"
    )]
    pub archive_restore_prefix: Vec<String>,

    #[arg(
        long = "cache-tag",
        hide = true,
        value_name = "TAG",
        help = "Internal integration flag: prefix planned archive tags"
    )]
    pub cache_tag: Option<String>,

    #[arg(
        long = "tool-tag-suffix",
        hide = true,
        value_name = "SUFFIX",
        help = "Internal integration flag: append a tool/version suffix to planned archive tags"
    )]
    pub tool_tag_suffix: Option<String>,

    #[arg(long, help = "Disable automatic platform suffix for tags")]
    pub no_platform: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback restore logic"
    )]
    pub no_git: bool,

    #[arg(long, help = "Force save even if cache entry already exists on server")]
    pub force: bool,

    #[arg(
        long,
        help = "Exclude files matching patterns (comma-separated, can be repeated)",
        value_delimiter = ','
    )]
    pub exclude: Vec<String>,

    #[arg(long, help = "Age recipient public key for encryption (age1...)")]
    pub recipient: Option<String>,

    #[arg(long, help = "Path to Age identity file for decryption")]
    pub identity: Option<String>,

    #[arg(
        long,
        help = "Start cache-registry proxy with the provided tag around command execution; command args may use {PORT}, {ENDPOINT}, and {CACHE_REF}"
    )]
    pub proxy: Option<String>,

    #[arg(
        long,
        value_name = "KEY=VALUE",
        help = "Attach low-cardinality metadata hints to proxy sessions, for example project=web or phase=seed (repeatable; also reads BORINGCACHE_PROXY_METADATA_HINTS)"
    )]
    pub metadata_hint: Vec<String>,

    #[arg(
        long,
        value_name = "NAME@REFERENCE",
        help = "Seed OCI manifest cache for selected repository refs on proxy startup (repeatable)"
    )]
    pub oci_prefetch_ref: Vec<String>,

    #[arg(
        long,
        hide = true,
        default_value = "metadata-only",
        value_parser = ["metadata-only", "bodies-before-ready", "bodies-background"],
        help = "Expert: OCI/Docker startup hydration policy for selected refs"
    )]
    pub oci_hydration: String,

    #[arg(long, help = "Skip startup warming and serve cache reads on demand")]
    pub on_demand: bool,

    #[arg(short, long, default_value = "5000")]
    pub port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(
        long = "endpoint-host",
        help = "Advertised host for wrapped clients when it differs from --host"
    )]
    pub endpoint_host: Option<String>,

    #[arg(long, help = "Run proxy reads only and skip cache writes")]
    pub read_only: bool,

    #[arg(long, help = "Run save phase even if command exits non-zero")]
    pub save_on_failure: bool,

    #[arg(long, help = "Skip restore phase")]
    pub skip_restore: bool,

    #[arg(long, help = "Skip save phase")]
    pub skip_save: bool,

    #[arg(
        long,
        help = "Exit with error if cache operations encounter backend failures"
    )]
    pub fail_on_cache_error: bool,

    #[arg(
        long,
        help = "Exit with error if cache entry is not found (before running command)"
    )]
    pub fail_on_cache_miss: bool,

    #[arg(long, help = "Print restore/save commands without executing")]
    pub dry_run: bool,

    #[arg(
        short,
        long,
        requires = "dry_run",
        help = "Print machine-readable dry-run plan for CI and scripts"
    )]
    pub json: bool,

    #[arg(
        last = true,
        required_unless_present = "dry_run",
        help = "Command to execute (after --); with --proxy, args may use {PORT}, {ENDPOINT}, and {CACHE_REF}"
    )]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Args)]
pub struct CheckArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: String,

    #[arg(help = "Comma-separated tags to check")]
    pub tags: String,

    #[arg(long, help = "Disable automatic platform suffix for tags")]
    pub no_platform: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback resolution"
    )]
    pub no_git: bool,

    #[arg(long, help = "Warn if any tag is not found (non-fatal)")]
    pub fail_on_miss: bool,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,

    #[arg(
        long,
        help = "Resolve and check only exact scoped tags (skip branch/default fallback candidates)"
    )]
    pub exact: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DeleteArgs {
    #[arg(help = "Cache tag to delete, or workspace when passing two positionals")]
    pub workspace_or_tag: String,

    #[arg(help = "Comma-separated tags to delete when passing an explicit workspace")]
    pub tags: Option<String>,

    #[arg(long, help = "Disable automatic platform suffix appending to tags")]
    pub no_platform: bool,

    #[arg(
        long,
        help = "Disable automatic git-based tag suffixing and fallback resolution"
    )]
    pub no_git: bool,
}

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    #[arg(help = "Cache tag or workspace when passing two positionals")]
    pub workspace_or_identifier: String,

    #[arg(help = "Cache tag or cache entry id when passing an explicit workspace")]
    pub identifier: Option<String>,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct LsArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(short, long, default_value = "20")]
    pub limit: u32,

    #[arg(long, default_value = "1")]
    pub page: u32,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct StatusArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(
        long,
        default_value = "24h",
        value_parser = ["1h", "6h", "24h", "7d", "30d"],
        help = "Time window for operator insights"
    )]
    pub period: String,

    #[arg(
        short,
        long,
        default_value = "5",
        value_parser = clap::value_parser!(u32).range(1..=10),
        help = "Maximum number of tools, sessions, and missed keys to show"
    )]
    pub limit: u32,

    #[arg(
        long,
        help = "Refresh the status view until interrupted",
        conflicts_with = "json"
    )]
    pub watch: bool,

    #[arg(
        long,
        default_value = "5",
        requires = "watch",
        value_parser = clap::value_parser!(u64).range(1..=3600),
        help = "Seconds between refreshes when --watch is enabled"
    )]
    pub interval: u64,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct SessionsArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(
        long,
        default_value = "24h",
        value_parser = ["1h", "6h", "24h", "7d", "30d"],
        help = "Time window for recent sessions"
    )]
    pub period: String,

    #[arg(
        short,
        long,
        default_value = "20",
        value_parser = clap::value_parser!(u32).range(1..=100),
        help = "Maximum number of sessions to show"
    )]
    pub limit: u32,

    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    pub page: u32,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct MissesArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(
        long,
        default_value = "24h",
        value_parser = ["1h", "6h", "24h", "7d", "30d"],
        help = "Time window for recent misses"
    )]
    pub period: String,

    #[arg(
        short,
        long,
        default_value = "20",
        value_parser = clap::value_parser!(u32).range(1..=100),
        help = "Maximum number of misses to show"
    )]
    pub limit: u32,

    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    pub page: u32,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct TagsArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(long, help = "Filter tags by substring")]
    pub filter: Option<String>,

    #[arg(long, help = "Include system and internal tags")]
    pub all: bool,

    #[arg(
        short,
        long,
        default_value = "20",
        value_parser = clap::value_parser!(u32).range(1..=100),
        help = "Maximum number of tags to show"
    )]
    pub limit: u32,

    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
    pub page: u32,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

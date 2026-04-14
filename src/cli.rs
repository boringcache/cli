use clap::{Parser, Subcommand};

#[doc(hidden)]
pub mod dispatch;
#[doc(hidden)]
pub mod preprocess;

#[derive(Subcommand)]
pub enum TokenCommands {
    #[command(name = "ls", visible_alias = "list", about = "List workspace tokens")]
    List {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(long, help = "Include revoked and expired tokens")]
        all: bool,

        #[arg(long, default_value_t = 20, help = "Number of tokens per page")]
        limit: u32,

        #[arg(long, default_value_t = 1, help = "Page number (1-based)")]
        page: u32,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(about = "Show one workspace token")]
    Show {
        #[arg(help = "Workspace name or token id")]
        workspace_or_token_id: String,

        #[arg(help = "Token id (omit when a default workspace is configured)")]
        token_id: Option<String>,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(about = "Create a workspace token")]
    Create {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(long, help = "Token name")]
        name: String,

        #[arg(
            long,
            default_value = "save",
            value_parser = ["restore", "save", "admin"],
            help = "Token access level"
        )]
        access: String,

        #[arg(
            long = "write-tag-prefix",
            value_name = "PREFIX",
            help = "Allowed write tag prefix for save tokens (repeatable)"
        )]
        write_tag_prefixes: Vec<String>,

        #[arg(
            long,
            value_parser = ["30d", "90d", "1y"],
            help = "Expiration shortcut"
        )]
        expires_in: Option<String>,

        #[arg(long, value_name = "YYYY-MM-DD", help = "Custom expiration date")]
        expires_on: Option<String>,

        #[arg(
            long,
            help = "Print shell export lines for the new secret",
            conflicts_with = "json"
        )]
        shell: bool,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(
        name = "create-ci",
        visible_alias = "ci",
        about = "Create restore/save CI token pair"
    )]
    CreateCi {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(long, help = "Optional token name prefix")]
        name: Option<String>,

        #[arg(
            long = "save-tag-prefix",
            value_name = "PREFIX",
            help = "Allowed save tag prefix for the save token (repeatable)"
        )]
        save_tag_prefixes: Vec<String>,

        #[arg(
            long,
            value_parser = ["30d", "90d", "1y"],
            help = "Expiration shortcut"
        )]
        expires_in: Option<String>,

        #[arg(long, value_name = "YYYY-MM-DD", help = "Custom expiration date")]
        expires_on: Option<String>,

        #[arg(
            long,
            help = "Print shell export lines for the new secrets",
            conflicts_with = "json"
        )]
        shell: bool,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(about = "Revoke a workspace token")]
    Revoke {
        #[arg(help = "Workspace name or token id")]
        workspace_or_token_id: String,

        #[arg(help = "Token id (omit when a default workspace is configured)")]
        token_id: Option<String>,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(about = "Rotate a workspace token")]
    Rotate {
        #[arg(help = "Workspace name or token id")]
        workspace_or_token_id: String,

        #[arg(help = "Token id (omit when a default workspace is configured)")]
        token_id: Option<String>,

        #[arg(long, help = "Optional replacement token name")]
        name: Option<String>,

        #[arg(
            long,
            value_parser = ["30d", "90d", "1y"],
            help = "Expiration shortcut"
        )]
        expires_in: Option<String>,

        #[arg(long, value_name = "YYYY-MM-DD", help = "Custom expiration date")]
        expires_on: Option<String>,

        #[arg(
            long,
            help = "Print shell export lines for the replacement secret",
            conflicts_with = "json"
        )]
        shell: bool,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },
}

#[derive(Parser)]
#[command(
    name = "boringcache",
    version,
    about = "High-performance cache management CLI for CI/CD workflows",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(
        long,
        global = true,
        help = "Require signed cache hits and fail if a returned server signature cannot be verified"
    )]
    pub require_server_signature: bool,
}

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

    #[arg(last = true, help = "Command to execute (after --)")]
    pub command: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    Auth {
        #[arg(short, long)]
        token: String,
    },

    #[command(about = "Sign in or create an account for this CLI session")]
    Login {
        #[arg(
            long,
            help = "Print the approval URL and wait without trying to open a local browser"
        )]
        manual: bool,

        #[arg(long, help = "Start sign-in by email for this CLI session")]
        email: Option<String>,

        #[arg(
            long,
            requires = "email",
            help = "Display name to use if this email needs a new account"
        )]
        name: Option<String>,

        #[arg(
            long,
            requires = "email",
            help = "Username to use if this email needs a new account"
        )]
        username: Option<String>,
    },

    #[command(about = "Check terminal cache setup, token scope, and workspace resolution")]
    Doctor {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(about = "Audit repo cache tag usage and suggest .boringcache.toml entries")]
    Audit {
        #[arg(help = "Repo root or a path inside the repo")]
        root: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "Limit the audit to specific relative or absolute paths (repeatable)"
        )]
        path: Vec<String>,

        #[arg(
            long,
            help = "Write missing entries and profiles into .boringcache.toml"
        )]
        write: bool,

        #[arg(long, help = "Print machine-readable output for CI and scripts")]
        json: bool,
    },

    #[command(
        about = "Open a full-screen workspace dashboard",
        visible_alias = "tui"
    )]
    Dashboard {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(
            long,
            default_value = "24h",
            value_parser = ["1h", "6h", "24h", "7d", "30d"],
            help = "Time window for operator insights"
        )]
        period: String,

        #[arg(
            short,
            long,
            default_value = "5",
            value_parser = clap::value_parser!(u32).range(1..=10),
            help = "Maximum number of tools, sessions, and missed keys to show"
        )]
        limit: u32,

        #[arg(
            long = "tag-limit",
            default_value = "25",
            value_parser = clap::value_parser!(u32).range(5..=100),
            help = "Number of tags to load per page"
        )]
        tag_limit: u32,

        #[arg(
            long,
            default_value = "15",
            value_parser = clap::value_parser!(u64).range(5..=3600),
            help = "Seconds between automatic refreshes"
        )]
        interval: u64,
    },

    #[command(subcommand, about = "Manage workspace tokens")]
    Token(TokenCommands),

    Mount {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "tag:path pair for the mount")]
        tag_path: String,

        #[arg(long, help = "Disable automatic platform suffix for tags")]
        no_platform: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback restore logic"
        )]
        no_git: bool,

        #[arg(short, long, help = "Enable verbose output")]
        verbose: bool,

        #[arg(
            long,
            help = "Allow clearing root, home, or current directory for restores"
        )]
        force: bool,

        #[arg(long, help = "Age recipient public key for encryption (age1...)")]
        recipient: Option<String>,

        #[arg(long, help = "Path to Age identity file for decryption")]
        identity: Option<String>,

        #[arg(
            long,
            help = "Require signed cache hits and fail if a returned server signature cannot be verified"
        )]
        require_server_signature: bool,
    },

    Save {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "One or more tag:path pairs (comma-separated)")]
        path_tag_pairs: String,

        #[arg(
            long,
            alias = "cross-os",
            help = "Disable automatic platform suffix for tags"
        )]
        no_platform: bool,

        #[arg(long, help = "Force save even if cache entry already exists on server")]
        force: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback restore logic"
        )]
        no_git: bool,

        #[arg(
            long,
            help = "Exclude files matching patterns (comma-separated, can be repeated)",
            value_delimiter = ','
        )]
        exclude: Vec<String>,

        #[arg(long, help = "Age recipient public key for encryption (age1...)")]
        recipient: Option<String>,

        #[arg(
            long,
            help = "Exit with error if save encounters cache/backend failures"
        )]
        fail_on_cache_error: bool,
    },

    Restore {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "One or more tag:path pairs (comma-separated)")]
        tag_path_pairs: String,

        #[arg(long, help = "Disable automatic platform suffix for tags")]
        no_platform: bool,

        #[arg(long, help = "Exit with error if cache entry is not found")]
        fail_on_cache_miss: bool,

        #[arg(long, help = "Check if a cache entry exists without downloading")]
        lookup_only: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback restore logic"
        )]
        no_git: bool,

        #[arg(long, help = "Path to Age identity file for decryption")]
        identity: Option<String>,

        #[arg(
            long,
            help = "Exit with error if restore encounters cache/backend failures"
        )]
        fail_on_cache_error: bool,
    },

    #[command(
        name = "run",
        visible_alias = "exec",
        about = "Wrap restore -> command -> save in one invocation",
        after_help = "Supported forms:\n  boringcache run [WORKSPACE] TAG_PATHS -- COMMAND...\n  boringcache run [WORKSPACE] --entry ENTRY[,ENTRY] -- COMMAND...\n  boringcache run [WORKSPACE] --profile PROFILE[,PROFILE] -- COMMAND...\n  boringcache run [WORKSPACE] -- COMMAND...\n\nManual TAG_PATHS are exclusive with --entry and --profile."
    )]
    Run {
        #[arg(
            value_name = "WORKSPACE_OR_TAG_PATHS",
            help = "Workspace name, or manual tag:path pairs when omitting WORKSPACE"
        )]
        workspace_or_tag_path: Option<String>,

        #[arg(help = "Manual tag:path pairs (comma-separated)")]
        tag_path_pairs: Option<String>,

        #[arg(
            long,
            value_name = "PROFILE",
            value_delimiter = ',',
            help = "Project cache profile(s) from .boringcache.toml (repeatable)"
        )]
        profile: Vec<String>,

        #[arg(
            long,
            value_name = "ENTRY",
            value_delimiter = ',',
            help = "Project or built-in cache entry/entries to resolve (repeatable)"
        )]
        entry: Vec<String>,

        #[arg(
            long,
            alias = "cross-os",
            help = "Disable automatic platform suffix for tags"
        )]
        no_platform: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback restore logic"
        )]
        no_git: bool,

        #[arg(long, help = "Force save even if cache entry already exists on server")]
        force: bool,

        #[arg(
            long,
            help = "Exclude files matching patterns (comma-separated, can be repeated)",
            value_delimiter = ','
        )]
        exclude: Vec<String>,

        #[arg(long, help = "Age recipient public key for encryption (age1...)")]
        recipient: Option<String>,

        #[arg(long, help = "Path to Age identity file for decryption")]
        identity: Option<String>,

        #[arg(
            long,
            help = "Start cache-registry proxy with the provided tag around command execution"
        )]
        proxy: Option<String>,

        #[arg(
            long,
            value_name = "KEY=VALUE",
            help = "Attach low-cardinality metadata hints to proxy sessions (repeatable; also reads BORINGCACHE_PROXY_METADATA_HINTS)"
        )]
        metadata_hint: Vec<String>,

        #[arg(short, long, default_value = "5000")]
        port: u16,

        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        #[arg(
            long = "endpoint-host",
            help = "Advertised host for wrapped clients when it differs from --host"
        )]
        endpoint_host: Option<String>,

        #[arg(long, help = "Run proxy reads only and skip cache writes")]
        read_only: bool,

        #[arg(long, help = "Run save phase even if command exits non-zero")]
        save_on_failure: bool,

        #[arg(long, help = "Skip restore phase")]
        skip_restore: bool,

        #[arg(long, help = "Skip save phase")]
        skip_save: bool,

        #[arg(
            long,
            help = "Exit with error if cache operations encounter backend failures"
        )]
        fail_on_cache_error: bool,

        #[arg(
            long,
            help = "Exit with error if cache entry is not found (before running command)"
        )]
        fail_on_cache_miss: bool,

        #[arg(long, help = "Print restore/save commands without executing")]
        dry_run: bool,

        #[arg(
            short,
            long,
            requires = "dry_run",
            help = "Print machine-readable dry-run plan for CI and scripts"
        )]
        json: bool,

        #[arg(
            last = true,
            required_unless_present = "dry_run",
            help = "Command to execute (after --)"
        )]
        command: Vec<String>,
    },

    #[command(about = "Run Turborepo against a local BoringCache proxy")]
    Turbo {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(about = "Run Nx against a local BoringCache proxy")]
    Nx {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(about = "Run Bazel against a local BoringCache proxy")]
    Bazel {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(about = "Run Gradle against a local BoringCache proxy")]
    Gradle {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(about = "Run Maven against a local BoringCache proxy")]
    Maven {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(about = "Run sccache against a local BoringCache proxy")]
    Sccache {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(name = "go", about = "Run Go against a local BoringCache proxy")]
    Go {
        #[command(flatten)]
        args: AdapterArgs,
    },

    #[command(about = "Run docker buildx build against a local BoringCache proxy")]
    Docker {
        #[command(flatten)]
        args: AdapterArgs,
    },

    Check {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Comma-separated tags to check")]
        tags: String,

        #[arg(long, help = "Disable automatic platform suffix for tags")]
        no_platform: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback resolution"
        )]
        no_git: bool,

        #[arg(long, help = "Warn if any tag is not found (non-fatal)")]
        fail_on_miss: bool,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,

        #[arg(
            long,
            help = "Resolve and check only exact scoped tags (skip branch/default fallback candidates)"
        )]
        exact: bool,
    },

    #[command(name = "rm", visible_alias = "delete", about = "Delete cache tags")]
    Delete {
        #[arg(help = "Cache tag to delete, or workspace when passing two positionals")]
        workspace_or_tag: String,

        #[arg(help = "Comma-separated tags to delete when passing an explicit workspace")]
        tags: Option<String>,

        #[arg(long, help = "Disable automatic platform suffix appending to tags")]
        no_platform: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback resolution"
        )]
        no_git: bool,
    },

    #[command(
        about = "Inspect a cache entry by tag or cache entry id",
        visible_alias = "show"
    )]
    Inspect {
        #[arg(help = "Cache tag or workspace when passing two positionals")]
        workspace_or_identifier: String,

        #[arg(help = "Cache tag or cache entry id when passing an explicit workspace")]
        identifier: Option<String>,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    Ls {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(short, long, default_value = "20")]
        limit: u32,

        #[arg(long, default_value = "1")]
        page: u32,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(
        about = "Show workspace status, cache health, and operator insights",
        visible_alias = "overview"
    )]
    Status {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(
            long,
            default_value = "24h",
            value_parser = ["1h", "6h", "24h", "7d", "30d"],
            help = "Time window for operator insights"
        )]
        period: String,

        #[arg(
            short,
            long,
            default_value = "5",
            value_parser = clap::value_parser!(u32).range(1..=10),
            help = "Maximum number of tools, sessions, and missed keys to show"
        )]
        limit: u32,

        #[arg(
            long,
            help = "Refresh the status view until interrupted",
            conflicts_with = "json"
        )]
        watch: bool,

        #[arg(
            long,
            default_value = "5",
            requires = "watch",
            value_parser = clap::value_parser!(u64).range(1..=3600),
            help = "Seconds between refreshes when --watch is enabled"
        )]
        interval: u64,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(about = "Show recent cache sessions and execution context")]
    Sessions {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(
            long,
            default_value = "24h",
            value_parser = ["1h", "6h", "24h", "7d", "30d"],
            help = "Time window for recent sessions"
        )]
        period: String,

        #[arg(
            short,
            long,
            default_value = "20",
            value_parser = clap::value_parser!(u32).range(1..=100),
            help = "Maximum number of sessions to show"
        )]
        limit: u32,

        #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
        page: u32,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(about = "Show hot cache misses and recurring miss patterns")]
    Misses {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(
            long,
            default_value = "24h",
            value_parser = ["1h", "6h", "24h", "7d", "30d"],
            help = "Time window for recent misses"
        )]
        period: String,

        #[arg(
            short,
            long,
            default_value = "20",
            value_parser = clap::value_parser!(u32).range(1..=100),
            help = "Maximum number of misses to show"
        )]
        limit: u32,

        #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
        page: u32,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(about = "List active cache tags for a workspace")]
    Tags {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(long, help = "Filter tags by substring")]
        filter: Option<String>,

        #[arg(long, help = "Include system and internal tags")]
        all: bool,

        #[arg(
            short,
            long,
            default_value = "20",
            value_parser = clap::value_parser!(u32).range(1..=100),
            help = "Maximum number of tags to show"
        )]
        limit: u32,

        #[arg(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..))]
        page: u32,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(name = "use", about = "Choose or set the default workspace")]
    Use {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    Config {
        #[command(subcommand)]
        action: ConfigSubcommand,
    },

    #[command(about = "Setup encryption for a workspace")]
    SetupEncryption {
        #[arg(help = "Workspace to enable encryption for (org/project)")]
        workspace: Option<String>,

        #[arg(
            long,
            help = "Output path for the identity file (default: ~/.boringcache/age-identity.txt)"
        )]
        identity_output: Option<String>,
    },

    Workspaces {
        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(about = "Set up BoringCache for this project")]
    Onboard {
        #[arg(help = "Path to a specific CI/CD file to scan (scans project if omitted)")]
        path: Option<String>,

        #[arg(long, help = "Start onboarding by email for this CLI session")]
        email: Option<String>,

        #[arg(
            long,
            requires = "email",
            help = "Display name to use if this email needs a new account"
        )]
        name: Option<String>,

        #[arg(
            long,
            requires = "email",
            help = "Username to use if this email needs a new account"
        )]
        username: Option<String>,

        #[arg(long, help = "Apply changes without prompting")]
        apply: bool,

        #[arg(long, help = "Show changes without applying")]
        dry_run: bool,

        #[arg(
            long,
            help = "Print the approval URL and wait without trying to open a local browser"
        )]
        manual: bool,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(name = "optimize", hide = true, about = "Legacy alias for onboard")]
    Optimize {
        #[arg(help = "Path to a specific CI/CD file to scan (scans project if omitted)")]
        path: Option<String>,

        #[arg(long, help = "Start onboarding by email for this CLI session")]
        email: Option<String>,

        #[arg(
            long,
            requires = "email",
            help = "Display name to use if this email needs a new account"
        )]
        name: Option<String>,

        #[arg(
            long,
            requires = "email",
            help = "Username to use if this email needs a new account"
        )]
        username: Option<String>,

        #[arg(long, help = "Apply changes without prompting")]
        apply: bool,

        #[arg(long, help = "Show changes without applying")]
        dry_run: bool,

        #[arg(
            long,
            help = "Print the approval URL and wait without trying to open a local browser"
        )]
        manual: bool,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    #[command(
        name = "docker-registry",
        about = "Run a local cache registry proxy backed by BoringCache (OCI + Bazel + Gradle + Maven + Nx + Turborepo + sccache + Go)",
        visible_aliases = ["serve", "cache-registry"]
    )]
    Serve {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(
            help = "Comma-separated cache tags. All are human-facing OCI aliases; the first is the primary display tag"
        )]
        tag: String,

        #[arg(short, long, default_value = "5000")]
        port: u16,

        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        #[arg(long, help = "Disable automatic platform suffix for cache tags")]
        no_platform: bool,

        #[arg(long, help = "Disable automatic git suffix for cache tags")]
        no_git: bool,

        #[arg(
            long,
            value_name = "KEY=VALUE",
            help = "Attach low-cardinality metadata hints to proxy sessions (repeatable; also reads BORINGCACHE_PROXY_METADATA_HINTS)"
        )]
        metadata_hint: Vec<String>,

        #[arg(
            long,
            help = "Return strict backend/cache errors instead of best-effort cache responses"
        )]
        fail_on_cache_error: bool,

        #[arg(
            long,
            help = "Serve cache reads only and treat proxy writes as successful no-ops"
        )]
        read_only: bool,
    },

    #[command(
        name = "go-cacheprog",
        about = "Run a GOCACHEPROG adapter that reads/writes through a BoringCache cache-registry endpoint"
    )]
    GoCacheProg {
        #[arg(
            long,
            env = "BORINGCACHE_GOCACHEPROG_ENDPOINT",
            help = "Cache-registry base URL (example: http://127.0.0.1:5000)"
        )]
        endpoint: String,

        #[arg(
            long,
            env = "BORINGCACHE_GOCACHEPROG_TOKEN",
            help = "Optional bearer token for cache-registry requests"
        )]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    Get {
        key: String,

        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },

    Set {
        key: String,
        value: String,
    },

    List {
        #[arg(short, long, help = "Output in JSON format")]
        json: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn test_login_parses_email_signup_flags() {
        let cli = Cli::parse_from([
            "boringcache",
            "login",
            "--manual",
            "--email",
            "jane@example.com",
            "--name",
            "Jane Doe",
            "--username",
            "jane-doe",
        ]);

        match cli.command {
            Commands::Login {
                manual,
                email,
                name,
                username,
            } => {
                assert!(manual);
                assert_eq!(email.as_deref(), Some("jane@example.com"));
                assert_eq!(name.as_deref(), Some("Jane Doe"));
                assert_eq!(username.as_deref(), Some("jane-doe"));
            }
            _ => panic!("expected login command"),
        }
    }

    #[test]
    fn test_turbo_adapter_parses_workspace_and_command() {
        let cli = Cli::parse_from([
            "boringcache",
            "turbo",
            "--workspace",
            "my-org/my-app",
            "--tag",
            "turbo-main",
            "--endpoint-host",
            "host.docker.internal",
            "--",
            "pnpm",
            "turbo",
            "run",
            "build",
        ]);

        match cli.command {
            Commands::Turbo { args } => {
                assert_eq!(args.workspace.as_deref(), Some("my-org/my-app"));
                assert_eq!(args.tag.as_deref(), Some("turbo-main"));
                assert_eq!(args.endpoint_host.as_deref(), Some("host.docker.internal"));
                assert_eq!(args.command, vec!["pnpm", "turbo", "run", "build"]);
            }
            _ => panic!("expected turbo command"),
        }
    }
}

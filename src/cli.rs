use clap::{Parser, Subcommand};

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
}

#[derive(Subcommand)]
pub enum Commands {
    Auth {
        #[arg(short, long)]
        token: String,
    },

    Mount {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "tag:path pair for the mount")]
        tag_path: String,

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
    },

    Delete {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Comma-separated tags to delete")]
        tags: String,

        #[arg(long, help = "Disable automatic platform suffix appending to tags")]
        no_platform: bool,

        #[arg(
            long,
            help = "Disable automatic git-based tag suffixing and fallback resolution"
        )]
        no_git: bool,
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

    #[command(
        name = "docker-registry",
        about = "Run a local cache registry proxy backed by BoringCache (OCI + Bazel + Gradle + Nx + Turborepo + sccache + Go)",
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
            help = "Return strict backend/cache errors instead of best-effort cache responses"
        )]
        fail_on_cache_error: bool,
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

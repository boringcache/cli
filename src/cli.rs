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
    },

    Restore {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "One or more tag:path pairs (comma-separated)")]
        tag_path_pairs: String,

        #[arg(long, help = "Disable automatic platform suffix for tags")]
        no_platform: bool,

        #[arg(long, help = "Fail the workflow if cache entry is not found")]
        fail_on_cache_miss: bool,

        #[arg(long, help = "Check if a cache entry exists without downloading")]
        lookup_only: bool,
    },

    Delete {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Comma-separated tags to delete")]
        tags: String,

        #[arg(long, help = "Disable automatic platform suffix appending to tags")]
        no_platform: bool,
    },

    Ls {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: Option<String>,

        #[arg(short, long, default_value = "20")]
        limit: u32,

        #[arg(long, default_value = "1")]
        page: u32,
    },

    Config {
        #[command(subcommand)]
        action: ConfigSubcommand,
    },

    Workspaces,
}

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    Get { key: String },

    Set { key: String, value: String },

    List,
}

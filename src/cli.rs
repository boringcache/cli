use clap::{Parser, Subcommand, ValueEnum};

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

    Save {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "One or more path:tag pairs (comma-separated)")]
        path_tag_pairs: String,

        #[arg(short, long, value_enum, help = "Compression algorithm for blob")]
        compression: Option<CompressionChoice>,

        #[arg(long, help = "Human description for this cache")]
        description: Option<String>,

        #[arg(long)]
        all: bool,

        #[arg(
            long,
            help = "Disable platform suffixes in tags (e.g., ruby3.4.4 instead of ruby3.4.4-linux-x64)"
        )]
        no_platform: bool,
    },

    Restore {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "One or more tag:path pairs (comma-separated)")]
        tag_path_pairs: String,

        #[arg(
            long,
            help = "Extract all archived paths into current dir (if blob contains many)"
        )]
        all: bool,

        #[arg(
            long,
            help = "Disable platform suffixes in tags (e.g., ruby3.4.4 instead of ruby3.4.4-linux-x64)"
        )]
        no_platform: bool,
    },

    Delete {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Comma-separated tags to delete")]
        tags: String,
    },

    Ls {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

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

    Tag {
        #[command(subcommand)]
        action: TagSubcommand,
    },
}

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    Get { key: String },

    Set { key: String, value: String },

    List,
}

#[derive(Subcommand)]
pub enum TagSubcommand {
    List {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Filter tags by user tag name")]
        filter: Option<String>,

        #[arg(long, help = "Show detailed information including content hashes")]
        verbose: bool,
    },

    Move {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Source tag to move (e.g., ruby-3.4.4-linux-x64 or ruby-3.4.4)")]
        source_tag: String,

        #[arg(help = "Destination tag (e.g., ruby-legacy or ruby-3.4.4-backup)")]
        dest_tag: String,
    },

    Copy {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Source tag to copy")]
        source_tag: String,

        #[arg(help = "Destination tag")]
        dest_tag: String,
    },

    Info {
        #[arg(help = "Workspace name (org/project or user/project)")]
        workspace: String,

        #[arg(help = "Tag name to show info for")]
        tag: String,
    },
}

#[derive(ValueEnum, Clone, Copy)]
pub enum CompressionChoice {
    Lz4,
    Zstd,
}

#[derive(ValueEnum, Clone, Copy)]
pub enum OutputFormat {
    Shell,
    Json,
    GithubEnv,
}

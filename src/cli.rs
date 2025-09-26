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

        #[arg(help = "One or more tag:path pairs (comma-separated)")]
        path_tag_pairs: String,

        #[arg(short, long, value_enum, help = "Compression algorithm for blob")]
        compression: Option<CompressionChoice>,

        #[arg(long, help = "Human description for this cache")]
        description: Option<String>,

        #[arg(long)]
        all: bool,
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
}

#[derive(Subcommand)]
pub enum ConfigSubcommand {
    Get { key: String },

    Set { key: String, value: String },

    List,
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

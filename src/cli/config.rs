use clap::{Args, Subcommand};

#[derive(Debug, Clone, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigSubcommand,
}

#[derive(Debug, Clone, Subcommand)]
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

#[derive(Debug, Clone, Args)]
pub struct SetupEncryptionArgs {
    #[arg(help = "Workspace to enable encryption for (org/project)")]
    pub workspace: Option<String>,

    #[arg(
        long,
        help = "Output path for the identity file (default: ~/.boringcache/age-identity.txt)"
    )]
    pub identity_output: Option<String>,
}

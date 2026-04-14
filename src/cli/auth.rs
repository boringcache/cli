use clap::Subcommand;

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

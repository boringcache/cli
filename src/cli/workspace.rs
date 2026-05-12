use clap::Args;

#[derive(Debug, Clone, Args)]
pub struct DoctorArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(long, help = "Print machine-readable output for CI and scripts")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AuditArgs {
    #[arg(help = "Repo root or a path inside the repo")]
    pub root: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Limit the audit to specific relative or absolute paths (repeatable)"
    )]
    pub path: Vec<String>,

    #[arg(
        long,
        help = "Write missing entries and profiles into .boringcache.toml"
    )]
    pub write: bool,

    #[arg(long, help = "Print machine-readable output for CI and scripts")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct DashboardArgs {
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
        long = "tag-limit",
        default_value = "25",
        value_parser = clap::value_parser!(u32).range(5..=100),
        help = "Number of tags to load per page"
    )]
    pub tag_limit: u32,

    #[arg(
        long,
        default_value = "15",
        value_parser = clap::value_parser!(u64).range(5..=3600),
        help = "Seconds between automatic refreshes"
    )]
    pub interval: u64,
}

#[derive(Debug, Clone, Args)]
pub struct UseArgs {
    #[arg(help = "Workspace name (org/project or user/project)")]
    pub workspace: Option<String>,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct WorkspacesArgs {
    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct OnboardArgs {
    #[arg(
        help = "Path to a specific CI/CD file to scan (plain onboard connects, chooses a workspace, and scans the project)"
    )]
    pub path: Option<String>,

    #[arg(
        long,
        value_name = "NAMESPACE/WORKSPACE",
        help = "Workspace to write into repo config and optionally provision"
    )]
    pub workspace: Option<String>,

    #[arg(
        long,
        requires = "workspace",
        help = "Create or verify the workspace through the API"
    )]
    pub create_workspace: bool,

    #[arg(
        long,
        requires = "workspace",
        help = "Create split restore/save CI tokens for the workspace"
    )]
    pub create_ci_tokens: bool,

    #[arg(
        long,
        requires = "workspace",
        help = "Set BORINGCACHE_RESTORE_TOKEN and BORINGCACHE_SAVE_TOKEN GitHub repository secrets"
    )]
    pub github_secrets: bool,

    #[arg(
        long,
        requires = "github_secrets",
        value_name = "OWNER/REPO",
        help = "GitHub repository for secret updates; defaults to --workspace"
    )]
    pub github_repo: Option<String>,

    #[arg(
        long,
        requires = "github_secrets",
        help = "Rotate GitHub CI secrets even when both split token secrets already exist"
    )]
    pub rotate_ci_tokens: bool,

    #[arg(
        long,
        requires = "workspace",
        value_name = "NAME",
        help = "Display name to use when creating the workspace"
    )]
    pub workspace_name: Option<String>,

    #[arg(long, help = "Start onboarding by email for this CLI session")]
    pub email: Option<String>,

    #[arg(
        long,
        requires = "email",
        help = "Display name to use if this email needs a new account"
    )]
    pub name: Option<String>,

    #[arg(
        long,
        requires = "email",
        help = "Username to use if this email needs a new account"
    )]
    pub username: Option<String>,

    #[arg(long, help = "Apply changes without prompting")]
    pub apply: bool,

    #[arg(long, help = "Show changes without applying")]
    pub dry_run: bool,

    #[arg(
        long,
        help = "Print the approval URL and wait without trying to open a local browser"
    )]
    pub manual: bool,

    #[arg(short, long, help = "Output in JSON format")]
    pub json: bool,
}

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
    #[arg(help = "Path to a specific CI/CD file to scan (scans project if omitted)")]
    pub path: Option<String>,

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

use clap::{Parser, Subcommand};

mod adapters;
mod auth;
mod cache;
mod config;
mod proxy;
mod workspace;

#[doc(hidden)]
pub mod dispatch;
#[doc(hidden)]
pub mod preprocess;

pub use adapters::AdapterArgs;
pub use auth::{AuthArgs, LoginArgs, TokenCommands};
pub use cache::{
    CheckArgs, DeleteArgs, InspectArgs, LsArgs, MissesArgs, MountArgs, RestoreArgs, RunArgs,
    SaveArgs, SessionsArgs, StatusArgs, TagsArgs,
};
pub use config::{ConfigArgs, ConfigSubcommand, SetupEncryptionArgs};
pub use proxy::{GoCacheProgArgs, ServeArgs};
pub use workspace::{AuditArgs, DashboardArgs, DoctorArgs, OnboardArgs, UseArgs, WorkspacesArgs};

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

#[derive(Subcommand)]
pub enum Commands {
    Auth(AuthArgs),

    #[command(about = "Sign in or create an account for this CLI session")]
    Login(LoginArgs),

    #[command(about = "Check terminal cache setup, token scope, and workspace resolution")]
    Doctor(DoctorArgs),

    #[command(about = "Audit repo cache tag usage and suggest .boringcache.toml entries")]
    Audit(AuditArgs),

    #[command(about = "Open a full-screen workspace dashboard")]
    Dashboard(DashboardArgs),

    #[command(subcommand, about = "Manage workspace tokens")]
    Token(TokenCommands),

    Mount(MountArgs),

    Save(SaveArgs),

    Restore(RestoreArgs),

    #[command(
        name = "run",
        about = "Wrap restore -> command -> save in one invocation",
        after_help = "Supported forms:\n  boringcache run [WORKSPACE] TAG_PATHS -- COMMAND...\n  boringcache run [WORKSPACE] --entry ENTRY[,ENTRY] -- COMMAND...\n  boringcache run [WORKSPACE] --profile PROFILE[,PROFILE] -- COMMAND...\n  boringcache run [WORKSPACE] -- COMMAND...\n\nManual TAG_PATHS are exclusive with --entry and --profile."
    )]
    Run(RunArgs),

    #[command(about = "Run Turborepo against a local BoringCache proxy")]
    Turbo(AdapterArgs),

    #[command(about = "Run Nx against a local BoringCache proxy")]
    Nx(AdapterArgs),

    #[command(about = "Run Bazel against a local BoringCache proxy")]
    Bazel(AdapterArgs),

    #[command(about = "Run Gradle against a local BoringCache proxy")]
    Gradle(AdapterArgs),

    #[command(about = "Run Maven against a local BoringCache proxy")]
    Maven(AdapterArgs),

    #[command(about = "Run sccache against a local BoringCache proxy")]
    Sccache(AdapterArgs),

    #[command(name = "go", about = "Run Go against a local BoringCache proxy")]
    Go(AdapterArgs),

    #[command(about = "Run docker buildx build against a local BoringCache proxy")]
    Docker(AdapterArgs),

    Check(CheckArgs),

    #[command(name = "rm", visible_alias = "delete", about = "Delete cache tags")]
    Delete(DeleteArgs),

    #[command(about = "Inspect a cache entry by tag or cache entry id")]
    Inspect(InspectArgs),

    Ls(LsArgs),

    #[command(about = "Show workspace status, cache health, and operator insights")]
    Status(StatusArgs),

    #[command(about = "Show recent cache sessions and execution context")]
    Sessions(SessionsArgs),

    #[command(about = "Show hot cache misses and recurring miss patterns")]
    Misses(MissesArgs),

    #[command(about = "List active cache tags for a workspace")]
    Tags(TagsArgs),

    #[command(name = "use", about = "Choose or set the default workspace")]
    Use(UseArgs),

    Config(ConfigArgs),

    #[command(about = "Setup encryption for a workspace")]
    SetupEncryption(SetupEncryptionArgs),

    Workspaces(WorkspacesArgs),

    #[command(about = "Set up BoringCache for this project")]
    Onboard(OnboardArgs),

    #[command(
        name = "cache-registry",
        about = "Run a local cache registry proxy backed by BoringCache (OCI + Bazel + Gradle + Maven + Nx + Turborepo + sccache + Go)"
    )]
    Serve(ServeArgs),

    #[command(
        name = "go-cacheprog",
        about = "Run a GOCACHEPROG adapter that reads/writes through a BoringCache cache-registry endpoint"
    )]
    GoCacheProg(GoCacheProgArgs),
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
            Commands::Login(args) => {
                assert!(args.manual);
                assert_eq!(args.email.as_deref(), Some("jane@example.com"));
                assert_eq!(args.name.as_deref(), Some("Jane Doe"));
                assert_eq!(args.username.as_deref(), Some("jane-doe"));
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
            Commands::Turbo(args) => {
                assert_eq!(args.workspace.as_deref(), Some("my-org/my-app"));
                assert_eq!(args.tag.as_deref(), Some("turbo-main"));
                assert_eq!(args.endpoint_host.as_deref(), Some("host.docker.internal"));
                assert_eq!(args.command, vec!["pnpm", "turbo", "run", "build"]);
            }
            _ => panic!("expected turbo command"),
        }
    }
}

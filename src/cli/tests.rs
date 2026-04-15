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

use anyhow::Result;
use boring_cache_cli::{
    cli, commands,
    config::{self, Config},
    ui,
};
use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

fn resolve_effective_workspace(workspace: &str) -> Option<String> {
    if workspace.trim().is_empty() {
        None
    } else {
        Some(workspace.to_string())
    }
}

fn resolve_default_workspace() -> Option<String> {
    if let Some(workspace) = config::env_var("BORINGCACHE_DEFAULT_WORKSPACE") {
        if let Some(workspace) = resolve_effective_workspace(&workspace) {
            return Some(workspace);
        }
    }

    let config = Config::load().ok()?;
    let workspace = config.default_workspace?;
    resolve_effective_workspace(&workspace)
}

#[tokio::main]
async fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|panic_info| {
        ui::error(&format!("Fatal error: {panic_info}"));
        ui::error("Please check your system resources and try again.");
        std::process::exit(1);
    }));

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error")),
        )
        .init();

    let mut args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        let mut cmd = cli::Cli::command();
        cmd.print_help().expect("failed to print help");
        println!();
        return Ok(());
    }

    if args.len() >= 2 {
        let command = &args[1];
        if matches!(
            command.as_str(),
            "save" | "restore" | "delete" | "check" | "ls"
        ) {
            let positional_args: Vec<&String> =
                args[2..].iter().filter(|a| !a.starts_with('-')).collect();

            let needs_workspace_injection = match command.as_str() {
                "ls" => positional_args.is_empty(),

                "save" | "restore" => {
                    positional_args.len() == 1 && positional_args[0].contains(':')
                }

                "delete" | "check" => {
                    positional_args.len() == 1 && !positional_args[0].contains('/')
                }
                _ => false,
            };

            if needs_workspace_injection {
                if let Some(default_workspace) = resolve_default_workspace() {
                    if command == "ls" || positional_args.is_empty() {
                        args.push(default_workspace);
                    } else {
                        let first_pos_idx = args[2..]
                            .iter()
                            .position(|a| !a.starts_with('-'))
                            .map(|i| i + 2)
                            .unwrap_or(args.len());
                        args.insert(first_pos_idx, default_workspace);
                    }
                }
            }
        }
    }

    let cli = match cli::Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    print!("{e}");
                    std::process::exit(0);
                }
                _ => {
                    ui::error(&e.to_string());
                    std::process::exit(1);
                }
            }
        }
    };

    let result = match cli.command {
        cli::Commands::Auth { token } => commands::auth::execute(token).await,
        cli::Commands::Mount {
            workspace,
            tag_path,
            verbose,
            force,
            recipient,
            identity,
        } => {
            commands::mount::execute(workspace, tag_path, verbose, force, recipient, identity).await
        }
        cli::Commands::Save {
            workspace,
            path_tag_pairs,
            no_platform,
            force,
            no_git,
            exclude,
            recipient,
        } => {
            let tag_path_strings = path_tag_pairs
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();

            let effective_workspace = resolve_effective_workspace(&workspace);

            commands::save::execute_batch_save(
                effective_workspace,
                tag_path_strings,
                cli.verbose,
                no_platform,
                no_git,
                force,
                exclude,
                recipient,
            )
            .await
        }
        cli::Commands::Restore {
            workspace,
            tag_path_pairs,
            no_platform,
            fail_on_cache_miss,
            lookup_only,
            no_git,
            identity,
        } => {
            let tag_path_strings = tag_path_pairs
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();

            let effective_workspace = resolve_effective_workspace(&workspace);

            commands::restore::execute_batch_restore(
                effective_workspace,
                tag_path_strings,
                cli.verbose,
                no_platform,
                no_git,
                fail_on_cache_miss,
                lookup_only,
                identity,
            )
            .await
        }
        cli::Commands::Check {
            workspace,
            tags,
            no_platform,
            no_git,
            fail_on_miss,
            json,
        } => {
            let tag_list: Vec<String> = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let effective_workspace = resolve_effective_workspace(&workspace);

            commands::check::execute(
                effective_workspace,
                tag_list,
                no_platform,
                no_git,
                fail_on_miss,
                json,
            )
            .await
        }
        cli::Commands::Delete {
            workspace,
            tags,
            no_platform,
            no_git,
        } => {
            let effective_workspace = resolve_effective_workspace(&workspace);
            for tag in tags.split(',') {
                commands::delete::execute(
                    effective_workspace.clone(),
                    tag.trim().to_string(),
                    cli.verbose,
                    no_platform,
                    no_git,
                )
                .await?;
            }
            Ok(())
        }
        cli::Commands::Config { action } => {
            use cli::ConfigSubcommand;
            use commands::config::ConfigAction;

            let config_action = match action {
                ConfigSubcommand::Get { key } => ConfigAction::Get { key },
                ConfigSubcommand::Set { key, value } => ConfigAction::Set { key, value },
                ConfigSubcommand::List => ConfigAction::List,
            };

            commands::config::execute(config_action).await
        }
        cli::Commands::Ls {
            workspace,
            limit,
            page,
        } => commands::ls::execute(workspace, Some(limit), Some(page), cli.verbose).await,
        cli::Commands::SetupEncryption {
            workspace,
            identity_output,
        } => commands::setup_encryption::execute(workspace, identity_output).await,
        cli::Commands::Workspaces => commands::workspaces::execute().await,
        cli::Commands::Serve {
            workspace,
            port,
            host,
        } => commands::serve::execute(workspace, host, port).await,
    };

    handle_result(result)
}

fn handle_result(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                match io_err.kind() {
                    std::io::ErrorKind::BrokenPipe => {
                        ui::error("Connection interrupted");
                        std::process::exit(141);
                    }
                    std::io::ErrorKind::OutOfMemory => {
                        ui::error(
                            "Out of memory - try reducing cache size or splitting the cache entry",
                        );
                        std::process::exit(1);
                    }
                    _ => {
                        ui::error(&format!("IO Error: {e}"));
                        std::process::exit(1);
                    }
                }
            } else {
                let error_msg = format!("{:?}", e);
                if error_msg.contains("Caused by:") {
                    ui::error(&error_msg);
                } else {
                    ui::error(&format!("Error: {e}"));
                }
                std::process::exit(1);
            }
        }
    }
}

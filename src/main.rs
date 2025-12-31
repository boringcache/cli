use anyhow::Result;
use boring_cache_cli::{cli, commands, ui};
use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

fn resolve_effective_workspace(workspace: &str) -> Option<String> {
    if workspace.trim().is_empty() {
        None
    } else {
        Some(workspace.to_string())
    }
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

    if let Ok(default_workspace) = std::env::var("BORINGCACHE_DEFAULT_WORKSPACE") {
        if args.len() >= 2 {
            let command = &args[1];
            if matches!(command.as_str(), "save" | "restore" | "delete" | "ls") {
                // Collect positional arguments (non-flag arguments after the command)
                let positional_args: Vec<&String> =
                    args[2..].iter().filter(|a| !a.starts_with('-')).collect();

                let needs_workspace_injection = match command.as_str() {
                    // ls: no positional args means workspace is missing
                    "ls" => positional_args.is_empty(),
                    // save/restore: 1 positional arg with ':' means it's tag:pairs, workspace missing
                    "save" | "restore" => {
                        positional_args.len() == 1 && positional_args[0].contains(':')
                    }
                    // delete: 1 positional arg without '/' means it's tags (not workspace/tags), workspace missing
                    "delete" => positional_args.len() == 1 && !positional_args[0].contains('/'),
                    _ => false,
                };

                if needs_workspace_injection {
                    // Find the position to insert workspace (after command, before first positional arg)
                    if command == "ls" || positional_args.is_empty() {
                        args.push(default_workspace);
                    } else {
                        // Find index of first positional arg
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
        } => commands::mount::execute(workspace, tag_path, verbose).await,
        cli::Commands::Save {
            workspace,
            path_tag_pairs,
            no_platform,
            force,
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
                force,
            )
            .await
        }
        cli::Commands::Restore {
            workspace,
            tag_path_pairs,
            no_platform,
            fail_on_cache_miss,
            lookup_only,
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
                fail_on_cache_miss,
                lookup_only,
            )
            .await
        }
        cli::Commands::Delete {
            workspace,
            tags,
            no_platform,
        } => {
            let effective_workspace = resolve_effective_workspace(&workspace);
            for tag in tags.split(',') {
                commands::delete::execute(
                    effective_workspace.clone(),
                    tag.trim().to_string(),
                    cli.verbose,
                    no_platform,
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
        cli::Commands::Workspaces => commands::workspaces::execute().await,
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
                // Show full error chain for better debugging
                let error_msg = format!("{:?}", e); // This shows the full error chain
                if error_msg.contains("Caused by:") {
                    // anyhow already formats the chain nicely
                    ui::error(&error_msg);
                } else {
                    ui::error(&format!("Error: {e}"));
                }
                std::process::exit(1);
            }
        }
    }
}

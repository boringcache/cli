use anyhow::Result;
use boring_cache_cli::{cli, commands, ui};
use clap::Parser;
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

    if let Ok(default_workspace) = std::env::var("BORINGCACHE_DEFAULT_WORKSPACE") {
        if args.len() >= 2 {
            let command = &args[1];
            if matches!(command.as_str(), "save" | "restore" | "delete" | "ls") {
                let needs_workspace_injection = match command.as_str() {
                    "ls" => args.len() == 2,
                    "save" | "restore" | "delete" => {
                        args.len() >= 3 && (args[2].contains(':') || args[2].contains(','))
                    }
                    _ => false,
                };

                if needs_workspace_injection {
                    if command == "ls" {
                        args.push(default_workspace);
                    } else {
                        args.insert(2, default_workspace);
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
        cli::Commands::Save {
            workspace,
            path_tag_pairs,
            compression,
            description,
            all: _,
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
                compression,
                description,
                cli.verbose,
                no_platform,
                force,
            )
            .await
        }
        cli::Commands::Restore {
            workspace,
            tag_path_pairs,
            all: _,
            no_platform,
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
        } => {
            let effective_workspace = resolve_effective_workspace(&workspace);
            commands::ls::execute(effective_workspace, Some(limit), Some(page), cli.verbose).await
        }
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
                        ui::error("Out of memory - try reducing cache size or using --compression");
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

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

fn long_option_requires_value(command: &str, option: &str) -> bool {
    match command {
        "save" => matches!(option, "--exclude" | "--recipient"),
        "restore" => matches!(option, "--identity"),
        "ls" => matches!(option, "--limit" | "--page"),
        "serve" | "docker-registry" | "cache-registry" => matches!(option, "--host" | "--port"),
        _ => false,
    }
}

fn short_option_requires_value(command: &str, option: &str) -> bool {
    match command {
        "serve" | "docker-registry" | "cache-registry" => {
            option == "-p" || (option.starts_with("-p") && option.len() > 2)
        }
        _ => false,
    }
}

fn positional_args_with_indices<'a>(
    command: &str,
    args_after_command: &'a [String],
) -> Vec<(usize, &'a String)> {
    let mut positional = Vec::new();
    let mut skip_next = false;
    let mut positional_mode = false;

    for (index, arg) in args_after_command.iter().enumerate() {
        if positional_mode {
            positional.push((index, arg));
            continue;
        }

        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "--" {
            positional_mode = true;
            continue;
        }

        if arg.starts_with("--") {
            let option_name = arg.split('=').next().unwrap_or(arg.as_str());
            if !arg.contains('=') && long_option_requires_value(command, option_name) {
                skip_next = true;
            }
            continue;
        }

        if arg.starts_with('-') && arg != "-" {
            if short_option_requires_value(command, arg) && arg.len() == 2 {
                skip_next = true;
            }
            continue;
        }

        positional.push((index, arg));
    }

    positional
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
            "save"
                | "restore"
                | "delete"
                | "check"
                | "ls"
                | "serve"
                | "docker-registry"
                | "cache-registry"
        ) {
            let positional_args = positional_args_with_indices(command, &args[2..]);

            let needs_workspace_injection = match command.as_str() {
                "ls" => positional_args.is_empty(),

                "save" | "restore" => {
                    positional_args.len() == 1 && positional_args[0].1.contains(':')
                }

                "delete" | "check" => {
                    positional_args.len() == 1 && !positional_args[0].1.contains('/')
                }
                "serve" | "docker-registry" | "cache-registry" => positional_args
                    .first()
                    .map(|(_, arg)| !arg.contains('/'))
                    .unwrap_or(false),
                _ => false,
            };

            if needs_workspace_injection {
                if let Some(default_workspace) = resolve_default_workspace() {
                    if command == "ls" || positional_args.is_empty() {
                        args.push(default_workspace);
                    } else {
                        let first_pos_idx = positional_args[0].0 + 2;
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
            tag,
            port,
            host,
            no_platform,
            no_git,
        } => commands::serve::execute(workspace, tag, host, port, no_platform, no_git).await,
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

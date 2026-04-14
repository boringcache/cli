use anyhow::Result;
use boring_cache_cli::{cli, command_support, commands, config, exit_code::ExitCodeError, ui};
use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

fn resolve_effective_workspace(workspace: &str) -> Option<String> {
    if workspace.trim().is_empty() {
        None
    } else {
        Some(workspace.to_string())
    }
}

fn long_option_requires_value(command: &str, option: &str) -> bool {
    match command {
        "save" => matches!(option, "--exclude" | "--recipient"),
        "restore" => matches!(option, "--identity"),
        "run" | "exec" => matches!(
            option,
            "--exclude"
                | "--recipient"
                | "--identity"
                | "--proxy"
                | "--metadata-hint"
                | "--host"
                | "--endpoint-host"
                | "--port"
        ),
        "ls" => matches!(option, "--limit" | "--page"),
        "serve" | "docker-registry" | "cache-registry" => {
            matches!(option, "--host" | "--port" | "--metadata-hint")
        }
        _ => false,
    }
}

fn short_option_requires_value(command: &str, option: &str) -> bool {
    match command {
        "run" | "exec" => option == "-p" || (option.starts_with("-p") && option.len() > 2),
        "serve" | "docker-registry" | "cache-registry" => {
            option == "-p" || (option.starts_with("-p") && option.len() > 2)
        }
        _ => false,
    }
}

fn split_comma_values(value: String) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn split_run_positionals(
    workspace_or_tag_path: Option<String>,
    tag_path_pairs: Option<String>,
) -> Result<(Option<String>, Vec<String>)> {
    match (workspace_or_tag_path, tag_path_pairs) {
        (Some(first), Some(_)) if first.contains(':') => Err(anyhow::anyhow!(
            "When omitting WORKSPACE, pass manual TAG_PATHS as the first positional only."
        )),
        (Some(first), Some(second)) => Ok((
            resolve_effective_workspace(&first),
            split_comma_values(second),
        )),
        (Some(first), None) if first.contains(':') => Ok((None, split_comma_values(first))),
        (Some(first), None) => Ok((resolve_effective_workspace(&first), Vec::new())),
        (None, Some(second)) => Ok((None, split_comma_values(second))),
        (None, None) => Ok((None, Vec::new())),
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

            if needs_workspace_injection
                && let Some(default_workspace) = command_support::configured_workspace()
            {
                if command == "ls" || positional_args.is_empty() {
                    args.push(default_workspace);
                } else {
                    let first_pos_idx = positional_args[0].0 + 2;
                    args.insert(first_pos_idx, default_workspace);
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

    let require_server_signature =
        cli.require_server_signature || config::env_bool("BORINGCACHE_REQUIRE_SERVER_SIGNATURE");

    let result = match cli.command {
        cli::Commands::Auth { token } => commands::auth::execute(token).await,
        cli::Commands::Login {
            manual,
            email,
            name,
            username,
        } => commands::login::execute(manual, email, name, username).await,
        cli::Commands::Doctor { workspace, json } => {
            commands::doctor::execute(workspace, json).await
        }
        cli::Commands::Audit {
            root,
            path,
            write,
            json,
        } => commands::audit::execute_with_paths(root, path, write, json).await,
        cli::Commands::Dashboard {
            workspace,
            period,
            limit,
            tag_limit,
            interval,
        } => commands::dashboard::execute(workspace, period, limit, tag_limit, interval).await,
        cli::Commands::Token(token_command) => match token_command {
            cli::TokenCommands::List {
                workspace,
                all,
                limit,
                page,
                json,
            } => commands::token::list(workspace, all, limit, page, json).await,
            cli::TokenCommands::Show {
                workspace_or_token_id,
                token_id,
                json,
            } => commands::token::show(workspace_or_token_id, token_id, json).await,
            cli::TokenCommands::Create {
                workspace,
                name,
                access,
                write_tag_prefixes,
                expires_in,
                expires_on,
                shell,
                json,
            } => {
                commands::token::create(commands::token::CreateTokenOptions {
                    workspace_option: workspace,
                    name,
                    access_level: access,
                    write_tag_prefixes,
                    expires_in,
                    expires_on,
                    shell_output: shell,
                    json_output: json,
                })
                .await
            }
            cli::TokenCommands::CreateCi {
                workspace,
                name,
                save_tag_prefixes,
                expires_in,
                expires_on,
                shell,
                json,
            } => {
                commands::token::create_ci(
                    workspace,
                    name,
                    save_tag_prefixes,
                    expires_in,
                    expires_on,
                    shell,
                    json,
                )
                .await
            }
            cli::TokenCommands::Revoke {
                workspace_or_token_id,
                token_id,
                json,
            } => commands::token::revoke(workspace_or_token_id, token_id, json).await,
            cli::TokenCommands::Rotate {
                workspace_or_token_id,
                token_id,
                name,
                expires_in,
                expires_on,
                shell,
                json,
            } => {
                commands::token::rotate(
                    workspace_or_token_id,
                    token_id,
                    name,
                    expires_in,
                    expires_on,
                    shell,
                    json,
                )
                .await
            }
        },
        cli::Commands::Mount {
            workspace,
            tag_path,
            no_platform,
            no_git,
            verbose,
            force,
            recipient,
            identity,
            require_server_signature,
        } => {
            commands::mount::execute(
                workspace,
                tag_path,
                commands::mount::MountOptions {
                    no_platform,
                    no_git,
                    verbose,
                    force,
                    recipient,
                    identity,
                    require_server_signature,
                },
            )
            .await
        }
        cli::Commands::Save {
            workspace,
            path_tag_pairs,
            no_platform,
            force,
            no_git,
            exclude,
            recipient,
            fail_on_cache_error,
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
                fail_on_cache_error,
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
            fail_on_cache_error,
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
                fail_on_cache_error,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Run {
            workspace_or_tag_path,
            tag_path_pairs,
            profile,
            entry,
            no_platform,
            no_git,
            force,
            exclude,
            recipient,
            identity,
            proxy,
            metadata_hint,
            host,
            endpoint_host,
            port,
            read_only,
            save_on_failure,
            skip_restore,
            skip_save,
            fail_on_cache_error,
            fail_on_cache_miss,
            dry_run,
            json,
            command,
        } => {
            let (effective_workspace, tag_path_strings) =
                split_run_positionals(workspace_or_tag_path, tag_path_pairs)?;

            commands::run::execute(
                effective_workspace,
                tag_path_strings,
                profile,
                entry,
                cli.verbose,
                require_server_signature,
                no_platform,
                no_git,
                force,
                exclude,
                recipient,
                identity,
                proxy,
                metadata_hint,
                host,
                endpoint_host,
                port,
                read_only,
                save_on_failure,
                skip_restore,
                skip_save,
                fail_on_cache_error,
                fail_on_cache_miss,
                dry_run,
                json,
                command,
            )
            .await
        }
        cli::Commands::Turbo { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Turbo,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Nx { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Nx,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Bazel { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Bazel,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Gradle { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Gradle,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Maven { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Maven,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Sccache { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Sccache,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Go { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Go,
                args,
                cli.verbose,
                require_server_signature,
            )
            .await
        }
        cli::Commands::Docker { args } => {
            commands::adapter::adapter_execute(
                commands::adapter::AdapterKind::Docker,
                args,
                cli.verbose,
                require_server_signature,
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
            exact,
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
                commands::check::CheckOptions {
                    no_platform,
                    no_git,
                    fail_on_miss,
                    json_output: json,
                    require_server_signature,
                    exact,
                },
            )
            .await
        }
        cli::Commands::Delete {
            workspace_or_tag,
            tags,
            no_platform,
            no_git,
        } => {
            commands::delete::execute(workspace_or_tag, tags, cli.verbose, no_platform, no_git)
                .await
        }
        cli::Commands::Inspect {
            workspace_or_identifier,
            identifier,
            json,
        } => commands::inspect::execute(workspace_or_identifier, identifier, json).await,
        cli::Commands::Config { action } => {
            use cli::ConfigSubcommand;
            use commands::config::ConfigAction;

            let config_action = match action {
                ConfigSubcommand::Get { key, json } => ConfigAction::Get { key, json },
                ConfigSubcommand::Set { key, value } => ConfigAction::Set { key, value },
                ConfigSubcommand::List { json } => ConfigAction::List { json },
            };

            commands::config::execute(config_action).await
        }
        cli::Commands::Ls {
            workspace,
            limit,
            page,
            json,
        } => commands::ls::execute(workspace, Some(limit), Some(page), cli.verbose, json).await,
        cli::Commands::Status {
            workspace,
            period,
            limit,
            watch,
            interval,
            json,
        } => commands::status::execute(workspace, period, limit, watch, interval, json).await,
        cli::Commands::Sessions {
            workspace,
            period,
            limit,
            page,
            json,
        } => commands::sessions::execute(workspace, period, limit, page, json).await,
        cli::Commands::Misses {
            workspace,
            period,
            limit,
            page,
            json,
        } => commands::misses::execute(workspace, period, limit, page, json).await,
        cli::Commands::Tags {
            workspace,
            filter,
            all,
            limit,
            page,
            json,
        } => commands::tags::execute(workspace, filter, all, limit, page, json).await,
        cli::Commands::Use { workspace, json } => {
            commands::use_workspace::execute(workspace, json).await
        }
        cli::Commands::SetupEncryption {
            workspace,
            identity_output,
        } => commands::setup_encryption::execute(workspace, identity_output).await,
        cli::Commands::Workspaces { json } => commands::workspaces::execute(json).await,
        cli::Commands::Onboard {
            path,
            email,
            name,
            username,
            apply,
            dry_run,
            manual,
            json,
        }
        | cli::Commands::Optimize {
            path,
            email,
            name,
            username,
            apply,
            dry_run,
            manual,
            json,
        } => {
            commands::onboard::execute(path, email, name, username, apply, dry_run, manual, json)
                .await
        }
        cli::Commands::Serve {
            workspace,
            tag,
            port,
            host,
            no_platform,
            no_git,
            metadata_hint,
            fail_on_cache_error,
            read_only,
        } => {
            commands::serve::execute(
                workspace,
                tag,
                host,
                port,
                no_platform,
                no_git,
                metadata_hint,
                fail_on_cache_error,
                read_only,
            )
            .await
        }
        cli::Commands::GoCacheProg { endpoint, token } => {
            commands::go_cacheprog::execute(endpoint, token, cli.verbose).await
        }
    };

    handle_result(result)
}

fn handle_result(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(exit_code_error) = e.downcast_ref::<ExitCodeError>() {
                if let Some(message) = exit_code_error.message() {
                    ui::error(message);
                }
                std::process::exit(exit_code_error.code());
            }

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

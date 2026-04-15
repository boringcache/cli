use anyhow::Result;

use crate::{commands, exit_code::ExitCodeError, ui};

use super::{Cli, Commands, ConfigSubcommand, TokenCommands};

fn resolve_effective_workspace(workspace: &str) -> Option<String> {
    if workspace.trim().is_empty() {
        None
    } else {
        Some(workspace.to_string())
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

async fn execute_token(command: TokenCommands) -> Result<()> {
    match command {
        TokenCommands::List {
            workspace,
            all,
            limit,
            page,
            json,
        } => commands::token::list(workspace, all, limit, page, json).await,
        TokenCommands::Show {
            workspace_or_token_id,
            token_id,
            json,
        } => commands::token::show(workspace_or_token_id, token_id, json).await,
        TokenCommands::Create {
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
        TokenCommands::CreateCi {
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
        TokenCommands::Revoke {
            workspace_or_token_id,
            token_id,
            json,
        } => commands::token::revoke(workspace_or_token_id, token_id, json).await,
        TokenCommands::Rotate {
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
    }
}

async fn execute_adapter(
    kind: commands::adapter::AdapterKind,
    args: super::AdapterArgs,
    verbose: bool,
    require_server_signature: bool,
) -> Result<()> {
    commands::adapter::adapter_execute(kind, args, verbose, require_server_signature).await
}

pub async fn execute(cli: Cli, require_server_signature: bool) -> Result<()> {
    let verbose = cli.verbose;

    match cli.command {
        Commands::Auth(args) => commands::auth::execute(args.token).await,
        Commands::Login(args) => {
            commands::login::execute(args.manual, args.email, args.name, args.username).await
        }
        Commands::Doctor(args) => commands::doctor::execute(args.workspace, args.json).await,
        Commands::Audit(args) => {
            commands::audit::execute_with_paths(args.root, args.path, args.write, args.json).await
        }
        Commands::Dashboard(args) => {
            commands::dashboard::execute(
                args.workspace,
                args.period,
                args.limit,
                args.tag_limit,
                args.interval,
            )
            .await
        }
        Commands::Token(command) => execute_token(command).await,
        Commands::Mount(args) => {
            commands::mount::execute(
                args.workspace,
                args.tag_path,
                commands::mount::MountOptions {
                    no_platform: args.no_platform,
                    no_git: args.no_git,
                    verbose: args.verbose,
                    force: args.force,
                    recipient: args.recipient,
                    identity: args.identity,
                    require_server_signature: args.require_server_signature,
                },
            )
            .await
        }
        Commands::Save(args) => {
            let tag_path_strings = split_comma_values(args.path_tag_pairs);
            let effective_workspace = resolve_effective_workspace(&args.workspace);

            commands::save::execute_batch_save(
                effective_workspace,
                tag_path_strings,
                verbose,
                args.no_platform,
                args.no_git,
                args.force,
                args.exclude,
                args.recipient,
                args.fail_on_cache_error,
            )
            .await
        }
        Commands::Restore(args) => {
            let tag_path_strings = split_comma_values(args.tag_path_pairs);
            let effective_workspace = resolve_effective_workspace(&args.workspace);

            commands::restore::execute_batch_restore(
                effective_workspace,
                tag_path_strings,
                verbose,
                args.no_platform,
                args.no_git,
                args.fail_on_cache_miss,
                args.lookup_only,
                args.identity,
                args.fail_on_cache_error,
                require_server_signature,
            )
            .await
        }
        Commands::Run(args) => {
            let (effective_workspace, tag_path_strings) =
                split_run_positionals(args.workspace_or_tag_path, args.tag_path_pairs)?;

            commands::run::execute(
                effective_workspace,
                tag_path_strings,
                args.profile,
                args.entry,
                args.archive_path,
                args.archive_tag_prefix,
                args.archive_restore_prefix,
                args.cache_tag,
                args.tool_tag_suffix,
                verbose,
                require_server_signature,
                args.no_platform,
                args.no_git,
                args.force,
                args.exclude,
                args.recipient,
                args.identity,
                args.proxy,
                args.metadata_hint,
                !args.on_demand,
                args.host,
                args.endpoint_host,
                args.port,
                args.read_only,
                args.save_on_failure,
                args.skip_restore,
                args.skip_save,
                args.fail_on_cache_error,
                args.fail_on_cache_miss,
                args.dry_run,
                args.json,
                args.command,
            )
            .await
        }
        Commands::Turbo(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Turbo,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Nx(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Nx,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Bazel(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Bazel,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Gradle(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Gradle,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Maven(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Maven,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Sccache(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Sccache,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Go(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Go,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Docker(args) => {
            execute_adapter(
                commands::adapter::AdapterKind::Docker,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Check(args) => {
            let tag_list = split_comma_values(args.tags);
            let effective_workspace = resolve_effective_workspace(&args.workspace);

            commands::check::execute(
                effective_workspace,
                tag_list,
                commands::check::CheckOptions {
                    no_platform: args.no_platform,
                    no_git: args.no_git,
                    fail_on_miss: args.fail_on_miss,
                    json_output: args.json,
                    require_server_signature,
                    exact: args.exact,
                },
            )
            .await
        }
        Commands::Delete(args) => {
            commands::delete::execute(
                args.workspace_or_tag,
                args.tags,
                verbose,
                args.no_platform,
                args.no_git,
            )
            .await
        }
        Commands::Inspect(args) => {
            commands::inspect::execute(args.workspace_or_identifier, args.identifier, args.json)
                .await
        }
        Commands::Config(args) => {
            let action = match args.action {
                ConfigSubcommand::Get { key, json } => {
                    commands::config::ConfigAction::Get { key, json }
                }
                ConfigSubcommand::Set { key, value } => {
                    commands::config::ConfigAction::Set { key, value }
                }
                ConfigSubcommand::List { json } => commands::config::ConfigAction::List { json },
            };

            commands::config::execute(action).await
        }
        Commands::Ls(args) => {
            commands::ls::execute(
                args.workspace,
                Some(args.limit),
                Some(args.page),
                verbose,
                args.json,
            )
            .await
        }
        Commands::Status(args) => {
            commands::status::execute(
                args.workspace,
                args.period,
                args.limit,
                args.watch,
                args.interval,
                args.json,
            )
            .await
        }
        Commands::Sessions(args) => {
            commands::sessions::execute(
                args.workspace,
                args.period,
                args.limit,
                args.page,
                args.json,
            )
            .await
        }
        Commands::Misses(args) => {
            commands::misses::execute(
                args.workspace,
                args.period,
                args.limit,
                args.page,
                args.json,
            )
            .await
        }
        Commands::Tags(args) => {
            commands::tags::execute(
                args.workspace,
                args.filter,
                args.all,
                args.limit,
                args.page,
                args.json,
            )
            .await
        }
        Commands::Use(args) => commands::use_workspace::execute(args.workspace, args.json).await,
        Commands::SetupEncryption(args) => {
            commands::setup_encryption::execute(args.workspace, args.identity_output).await
        }
        Commands::Workspaces(args) => commands::workspaces::execute(args.json).await,
        Commands::Onboard(args) => {
            commands::onboard::execute(
                args.path,
                args.email,
                args.name,
                args.username,
                args.apply,
                args.dry_run,
                args.manual,
                args.json,
            )
            .await
        }
        Commands::CacheRegistry(args) => {
            commands::cache_registry::execute(
                args.workspace,
                args.tag,
                args.host,
                args.port,
                args.no_platform,
                args.no_git,
                args.metadata_hint,
                !args.on_demand,
                args.fail_on_cache_error,
                args.read_only,
            )
            .await
        }
        Commands::GoCacheProg(args) => {
            commands::go_cacheprog::execute(args.endpoint, args.token, verbose).await
        }
    }
}

pub fn handle_result(result: Result<()>) -> Result<()> {
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

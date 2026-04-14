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
        Commands::Auth { token } => commands::auth::execute(token).await,
        Commands::Login {
            manual,
            email,
            name,
            username,
        } => commands::login::execute(manual, email, name, username).await,
        Commands::Doctor { workspace, json } => commands::doctor::execute(workspace, json).await,
        Commands::Audit {
            root,
            path,
            write,
            json,
        } => commands::audit::execute_with_paths(root, path, write, json).await,
        Commands::Dashboard {
            workspace,
            period,
            limit,
            tag_limit,
            interval,
        } => commands::dashboard::execute(workspace, period, limit, tag_limit, interval).await,
        Commands::Token(command) => execute_token(command).await,
        Commands::Mount {
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
        Commands::Save {
            workspace,
            path_tag_pairs,
            no_platform,
            force,
            no_git,
            exclude,
            recipient,
            fail_on_cache_error,
        } => {
            let tag_path_strings = split_comma_values(path_tag_pairs);
            let effective_workspace = resolve_effective_workspace(&workspace);

            commands::save::execute_batch_save(
                effective_workspace,
                tag_path_strings,
                verbose,
                no_platform,
                no_git,
                force,
                exclude,
                recipient,
                fail_on_cache_error,
            )
            .await
        }
        Commands::Restore {
            workspace,
            tag_path_pairs,
            no_platform,
            fail_on_cache_miss,
            lookup_only,
            no_git,
            identity,
            fail_on_cache_error,
        } => {
            let tag_path_strings = split_comma_values(tag_path_pairs);
            let effective_workspace = resolve_effective_workspace(&workspace);

            commands::restore::execute_batch_restore(
                effective_workspace,
                tag_path_strings,
                verbose,
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
        Commands::Run {
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
                verbose,
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
        Commands::Turbo { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Turbo,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Nx { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Nx,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Bazel { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Bazel,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Gradle { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Gradle,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Maven { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Maven,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Sccache { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Sccache,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Go { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Go,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Docker { args } => {
            execute_adapter(
                commands::adapter::AdapterKind::Docker,
                args,
                verbose,
                require_server_signature,
            )
            .await
        }
        Commands::Check {
            workspace,
            tags,
            no_platform,
            no_git,
            fail_on_miss,
            json,
            exact,
        } => {
            let tag_list = split_comma_values(tags);
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
        Commands::Delete {
            workspace_or_tag,
            tags,
            no_platform,
            no_git,
        } => commands::delete::execute(workspace_or_tag, tags, verbose, no_platform, no_git).await,
        Commands::Inspect {
            workspace_or_identifier,
            identifier,
            json,
        } => commands::inspect::execute(workspace_or_identifier, identifier, json).await,
        Commands::Config { action } => {
            let action = match action {
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
        Commands::Ls {
            workspace,
            limit,
            page,
            json,
        } => commands::ls::execute(workspace, Some(limit), Some(page), verbose, json).await,
        Commands::Status {
            workspace,
            period,
            limit,
            watch,
            interval,
            json,
        } => commands::status::execute(workspace, period, limit, watch, interval, json).await,
        Commands::Sessions {
            workspace,
            period,
            limit,
            page,
            json,
        } => commands::sessions::execute(workspace, period, limit, page, json).await,
        Commands::Misses {
            workspace,
            period,
            limit,
            page,
            json,
        } => commands::misses::execute(workspace, period, limit, page, json).await,
        Commands::Tags {
            workspace,
            filter,
            all,
            limit,
            page,
            json,
        } => commands::tags::execute(workspace, filter, all, limit, page, json).await,
        Commands::Use { workspace, json } => {
            commands::use_workspace::execute(workspace, json).await
        }
        Commands::SetupEncryption {
            workspace,
            identity_output,
        } => commands::setup_encryption::execute(workspace, identity_output).await,
        Commands::Workspaces { json } => commands::workspaces::execute(json).await,
        Commands::Onboard {
            path,
            email,
            name,
            username,
            apply,
            dry_run,
            manual,
            json,
        }
        | Commands::Optimize {
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
        Commands::Serve {
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
        Commands::GoCacheProg { endpoint, token } => {
            commands::go_cacheprog::execute(endpoint, token, verbose).await
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

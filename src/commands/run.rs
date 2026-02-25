use anyhow::{anyhow, Context, Result};
use std::process::Stdio;

use crate::commands::{restore, save, serve, utils};
use crate::exit_code::ExitCodeError;
use crate::ui;

const EXIT_CONFIG: i32 = 78;
const EXIT_COMMAND_NOT_FOUND: i32 = 127;
const PROXY_AUTH_TOKEN: &str = "boringcache";

#[derive(Debug)]
enum ChildOutcome {
    Exited(std::process::ExitStatus),
    Signaled(i32),
}

#[derive(Debug)]
struct ProxyContext {
    endpoint_host: String,
    port: u16,
    cache_ref: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: Vec<String>,
    recipient: Option<String>,
    identity: Option<String>,
    proxy: Option<String>,
    host: String,
    port: u16,
    save_on_failure: bool,
    skip_restore: bool,
    skip_save: bool,
    fail_on_cache_error: bool,
    fail_on_cache_miss: bool,
    dry_run: bool,
    command: Vec<String>,
) -> Result<()> {
    let workspace = utils::get_workspace_name(workspace)?;
    let archive_enabled = !tag_path_pairs.is_empty();
    let proxy_enabled = proxy.is_some();

    if !archive_enabled && !proxy_enabled {
        anyhow::bail!("Provide TAG_PATH_PAIRS, --proxy <TAG>, or both");
    }

    if archive_enabled {
        validate_archive_pairs(&tag_path_pairs, skip_restore, skip_save)?;
    }

    if dry_run {
        print_dry_run(
            &workspace,
            &tag_path_pairs,
            no_platform,
            no_git,
            force,
            &exclude,
            recipient.as_deref(),
            identity.as_deref(),
            proxy.as_deref(),
            &host,
            port,
            save_on_failure,
            skip_restore,
            skip_save,
            fail_on_cache_error,
            fail_on_cache_miss,
            &command,
        );
        return Ok(());
    }

    if archive_enabled && !skip_restore {
        let restore_result = restore::execute_batch_restore(
            Some(workspace.clone()),
            tag_path_pairs.clone(),
            verbose,
            no_platform,
            no_git,
            fail_on_cache_miss,
            false,
            identity.clone(),
            fail_on_cache_error,
        )
        .await;

        if let Err(error) = restore_result {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
    }

    let mut proxy_handle: Option<serve::ProxyServerHandle> = None;
    let mut proxy_context: Option<ProxyContext> = None;

    if let Some(proxy_tag) = proxy {
        let handle = serve::start_proxy_background(
            workspace.clone(),
            proxy_tag,
            host,
            port,
            no_platform,
            no_git,
            fail_on_cache_error,
        )
        .await
        .map_err(|error| ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)))?;

        let cache_ref = handle.cache_ref();
        proxy_context = Some(ProxyContext {
            endpoint_host: handle.endpoint_host().to_string(),
            port: handle.port(),
            cache_ref,
        });
        proxy_handle = Some(handle);
    }

    let child_outcome = spawn_command(&command, proxy_context.as_ref()).await;

    let child_outcome = match child_outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, false).await?;
            return Err(error);
        }
    };

    match child_outcome {
        ChildOutcome::Signaled(signal) => {
            shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, false).await?;
            Err(ExitCodeError::silent(128 + signal).into())
        }
        ChildOutcome::Exited(status) => {
            let command_succeeded = status.success();
            let command_exit_code = status_exit_code(&status);

            if archive_enabled && !skip_save && (command_succeeded || save_on_failure) {
                let save_result = save::execute_batch_save(
                    Some(workspace),
                    tag_path_pairs,
                    verbose,
                    no_platform,
                    no_git,
                    force,
                    exclude,
                    recipient,
                    fail_on_cache_error,
                )
                .await;

                if let Err(error) = save_result {
                    if fail_on_cache_error && command_succeeded {
                        shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, false)
                            .await?;
                        return Err(ExitCodeError::with_message(
                            EXIT_CONFIG,
                            format!("{:#}", error),
                        )
                        .into());
                    }
                }
            }

            shutdown_proxy_handle(proxy_handle.take(), fail_on_cache_error, command_succeeded)
                .await?;

            if command_exit_code == 0 {
                Ok(())
            } else {
                Err(ExitCodeError::silent(command_exit_code).into())
            }
        }
    }
}

fn validate_archive_pairs(
    tag_path_pairs: &[String],
    skip_restore: bool,
    skip_save: bool,
) -> Result<()> {
    if tag_path_pairs.is_empty() {
        anyhow::bail!("At least one tag:path pair is required");
    }

    if !skip_save {
        for pair in tag_path_pairs {
            utils::parse_save_format(pair).map_err(anyhow::Error::from)?;
        }
        return Ok(());
    }

    if !skip_restore {
        for pair in tag_path_pairs {
            utils::parse_restore_format(pair).map_err(anyhow::Error::from)?;
        }
    }

    Ok(())
}

async fn spawn_command(
    command: &[String],
    proxy_context: Option<&ProxyContext>,
) -> Result<ChildOutcome> {
    if command.is_empty() {
        return Err(anyhow!("Command is required after --"));
    }

    let prepared_command = if let Some(proxy_context) = proxy_context {
        substitute_proxy_placeholders(command, proxy_context.port, &proxy_context.cache_ref)
    } else {
        command.to_vec()
    };

    let mut process = tokio::process::Command::new(&prepared_command[0]);
    process
        .args(&prepared_command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(proxy_context) = proxy_context {
        inject_proxy_env(&mut process, proxy_context);
    }

    let mut child = process
        .spawn()
        .map_err(|error| map_spawn_error(error, &prepared_command[0]))?;

    wait_for_child(&mut child).await
}

fn inject_proxy_env(command: &mut tokio::process::Command, context: &ProxyContext) {
    let endpoint = format!("http://{}:{}", context.endpoint_host, context.port);
    command.env("NX_SELF_HOSTED_REMOTE_CACHE_SERVER", &endpoint);
    command.env("NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN", PROXY_AUTH_TOKEN);
    command.env("TURBO_API", &endpoint);
    command.env("TURBO_TOKEN", PROXY_AUTH_TOKEN);
    command.env("TURBO_TEAM", PROXY_AUTH_TOKEN);
    command.env(
        "GOCACHEPROG",
        format!("boringcache go-cacheprog --endpoint {}", endpoint),
    );
    command.env("RUSTC_WRAPPER", "sccache");
    command.env("SCCACHE_ENDPOINT", &endpoint);
    command.env("SCCACHE_BUCKET", "cache");
    command.env("SCCACHE_S3_USE_SSL", "false");
    command.env("SCCACHE_REGION", "local");
    command.env("BORINGCACHE_PROXY_PORT", context.port.to_string());
    command.env("BORINGCACHE_CACHE_REF", &context.cache_ref);
}

fn substitute_proxy_placeholders(command: &[String], port: u16, cache_ref: &str) -> Vec<String> {
    let port_value = port.to_string();
    command
        .iter()
        .map(|arg| {
            arg.replace("{PORT}", &port_value)
                .replace("{CACHE_REF}", cache_ref)
        })
        .collect()
}

#[cfg(unix)]
async fn wait_for_child(child: &mut tokio::process::Child) -> Result<ChildOutcome> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt()).context("Failed to install SIGINT handler")?;
    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to install SIGTERM handler")?;

    tokio::select! {
        status = child.wait() => {
            Ok(ChildOutcome::Exited(status.context("Failed to wait for command process")?))
        }
        _ = sigint.recv() => handle_signal(child, libc::SIGINT).await,
        _ = sigterm.recv() => handle_signal(child, libc::SIGTERM).await,
    }
}

#[cfg(unix)]
async fn handle_signal(child: &mut tokio::process::Child, signal: i32) -> Result<ChildOutcome> {
    if let Some(status) = child
        .try_wait()
        .context("Failed to inspect command status")?
    {
        return Ok(ChildOutcome::Exited(status));
    }

    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as i32, signal);
        }
    }

    let _ = child
        .wait()
        .await
        .context("Failed to wait for command after signal")?;
    Ok(ChildOutcome::Signaled(signal))
}

#[cfg(not(unix))]
async fn wait_for_child(child: &mut tokio::process::Child) -> Result<ChildOutcome> {
    let status = child
        .wait()
        .await
        .context("Failed to wait for command process")?;
    Ok(ChildOutcome::Exited(status))
}

fn map_spawn_error(error: std::io::Error, command: &str) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        ExitCodeError::with_message(
            EXIT_COMMAND_NOT_FOUND,
            format!("Command not found: {command}"),
        )
        .into()
    } else {
        ExitCodeError::with_message(
            EXIT_CONFIG,
            format!("Failed to spawn command '{command}': {error}"),
        )
        .into()
    }
}

fn status_exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

async fn shutdown_proxy_handle(
    proxy_handle: Option<serve::ProxyServerHandle>,
    fail_on_cache_error: bool,
    allow_override: bool,
) -> Result<()> {
    let Some(proxy_handle) = proxy_handle else {
        return Ok(());
    };

    if let Err(error) = proxy_handle.shutdown_and_flush().await {
        if fail_on_cache_error && allow_override {
            return Err(ExitCodeError::with_message(EXIT_CONFIG, format!("{:#}", error)).into());
        }
        ui::warn(&format!("Proxy shutdown warning: {:#}", error));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_dry_run(
    workspace: &str,
    tag_path_pairs: &[String],
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: &[String],
    recipient: Option<&str>,
    identity: Option<&str>,
    proxy: Option<&str>,
    host: &str,
    port: u16,
    save_on_failure: bool,
    skip_restore: bool,
    skip_save: bool,
    fail_on_cache_error: bool,
    fail_on_cache_miss: bool,
    command: &[String],
) {
    ui::info("[boringcache] Dry run:");

    if !tag_path_pairs.is_empty() && !skip_restore {
        let pairs = format!("\"{}\"", tag_path_pairs.join(","));
        let mut restore_parts = vec![
            "boringcache".to_string(),
            "restore".to_string(),
            workspace.to_string(),
            pairs.clone(),
        ];
        if no_platform {
            restore_parts.push("--no-platform".to_string());
        }
        if no_git {
            restore_parts.push("--no-git".to_string());
        }
        if fail_on_cache_miss {
            restore_parts.push("--fail-on-cache-miss".to_string());
        }
        if fail_on_cache_error {
            restore_parts.push("--fail-on-cache-error".to_string());
        }
        if let Some(identity) = identity {
            restore_parts.push("--identity".to_string());
            restore_parts.push(identity.to_string());
        }
        ui::info(&format!("[boringcache]   {}", restore_parts.join(" ")));
    }

    if let Some(proxy_tag) = proxy {
        let mut proxy_parts = vec![
            "boringcache".to_string(),
            "serve".to_string(),
            workspace.to_string(),
            proxy_tag.to_string(),
            "--host".to_string(),
            host.to_string(),
            "--port".to_string(),
            port.to_string(),
        ];
        if no_platform {
            proxy_parts.push("--no-platform".to_string());
        }
        if no_git {
            proxy_parts.push("--no-git".to_string());
        }
        if fail_on_cache_error {
            proxy_parts.push("--fail-on-cache-error".to_string());
        }
        ui::info(&format!("[boringcache]   {}", proxy_parts.join(" ")));
    }

    ui::info(&format!("[boringcache]   {}", command.join(" ")));

    if !tag_path_pairs.is_empty() && !skip_save {
        let pairs = format!("\"{}\"", tag_path_pairs.join(","));
        let mut save_parts = vec![
            "boringcache".to_string(),
            "save".to_string(),
            workspace.to_string(),
            pairs,
        ];
        if no_platform {
            save_parts.push("--no-platform".to_string());
        }
        if no_git {
            save_parts.push("--no-git".to_string());
        }
        if force {
            save_parts.push("--force".to_string());
        }
        if fail_on_cache_error {
            save_parts.push("--fail-on-cache-error".to_string());
        }
        if let Some(recipient) = recipient {
            save_parts.push("--recipient".to_string());
            save_parts.push(recipient.to_string());
        }
        for pattern in exclude {
            save_parts.push("--exclude".to_string());
            save_parts.push(pattern.clone());
        }
        ui::info(&format!("[boringcache]   {}", save_parts.join(" ")));
    }

    if save_on_failure && !tag_path_pairs.is_empty() {
        ui::info("[boringcache]   # save phase enabled for non-zero command exits");
    }
}

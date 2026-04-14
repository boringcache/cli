use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Stdio;

use crate::exit_code::ExitCodeError;

const EXIT_CONFIG: i32 = 78;
const EXIT_COMMAND_NOT_FOUND: i32 = 127;

pub(crate) const PROXY_AUTH_TOKEN: &str = "boringcache";

const SCCACHE_BACKEND_ENV_PREFIXES: &[&str] = &[
    "SCCACHE_S3_",
    "SCCACHE_GCS_",
    "SCCACHE_AZURE_",
    "SCCACHE_REDIS_",
    "SCCACHE_MEMCACHED_",
    "SCCACHE_GHA_",
    "SCCACHE_WEBDAV_",
];

const SCCACHE_BACKEND_ENV_EXACT: &[&str] = &[
    "SCCACHE_CONF",
    "SCCACHE_CACHED_CONF",
    "SCCACHE_ENDPOINT",
    "SCCACHE_BUCKET",
    "SCCACHE_REGION",
    "SCCACHE_REDIS",
    "SCCACHE_MEMCACHED",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_RUNTIME_TOKEN",
];

pub(crate) fn should_clear_sccache_backend_env_var(key: &str) -> bool {
    SCCACHE_BACKEND_ENV_EXACT.contains(&key)
        || SCCACHE_BACKEND_ENV_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

pub(crate) fn inherited_sccache_backend_env_vars() -> Vec<String> {
    inherited_sccache_backend_env_vars_from(std::env::vars_os().map(|(key, _)| key))
}

fn inherited_sccache_backend_env_vars_from<I>(keys: I) -> Vec<String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut env_vars = keys
        .into_iter()
        .filter_map(|key| key.into_string().ok())
        .filter(|key| should_clear_sccache_backend_env_var(key))
        .collect::<Vec<_>>();
    env_vars.sort();
    env_vars.dedup();
    env_vars
}

#[derive(Debug)]
pub(crate) enum ChildOutcome {
    Exited(std::process::ExitStatus),
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyContext {
    pub endpoint_host: String,
    pub port: u16,
    pub cache_ref: String,
}

impl ProxyContext {
    pub fn endpoint(&self) -> String {
        format!("http://{}:{}", self.endpoint_host, self.port)
    }
}

pub(crate) async fn spawn_command<F>(
    command: &[String],
    env_vars: &BTreeMap<String, String>,
    proxy_context: Option<&ProxyContext>,
    inject_proxy_env: F,
) -> Result<ChildOutcome>
where
    F: FnOnce(&mut tokio::process::Command, &ProxyContext),
{
    if command.is_empty() {
        anyhow::bail!("Command is required after --");
    }

    let prepared_command = if let Some(proxy_context) = proxy_context {
        substitute_proxy_placeholders(command, proxy_context)
    } else {
        command.to_vec()
    };

    let mut process = tokio::process::Command::new(&prepared_command[0]);
    process
        .args(&prepared_command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    process.envs(env_vars);

    if let Some(proxy_context) = proxy_context {
        inject_proxy_env(&mut process, proxy_context);
    }

    let mut child = process
        .spawn()
        .map_err(|error| map_spawn_error(error, &prepared_command[0]))?;

    wait_for_child(&mut child).await
}

pub(crate) fn substitute_proxy_placeholders(
    command: &[String],
    proxy_context: &ProxyContext,
) -> Vec<String> {
    let port_value = proxy_context.port.to_string();
    let endpoint = proxy_context.endpoint();
    command
        .iter()
        .map(|arg| {
            arg.replace("{PORT}", &port_value)
                .replace("{CACHE_REF}", &proxy_context.cache_ref)
                .replace("{ENDPOINT}", &endpoint)
        })
        .collect()
}

#[cfg(unix)]
pub(crate) async fn wait_for_child(child: &mut tokio::process::Child) -> Result<ChildOutcome> {
    use tokio::signal::unix::{SignalKind, signal};

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
pub(crate) async fn handle_signal(
    child: &mut tokio::process::Child,
    signal: i32,
) -> Result<ChildOutcome> {
    if let Some(status) = child
        .try_wait()
        .context("Failed to inspect command status")?
    {
        return Ok(ChildOutcome::Exited(status));
    }

    if let Some(pid) = child.id() {
        // SAFETY: `pid` comes from the live child process handle and `signal` is forwarded verbatim
        // to the OS. Failing `kill` here is non-fatal because we still wait on the child below.
        unsafe {
            libc::kill(pid as i32, signal);
        }
    }

    let status = child
        .wait()
        .await
        .context("Failed to wait for command after signal")?;
    Ok(ChildOutcome::Exited(status))
}

#[cfg(not(unix))]
pub(crate) async fn wait_for_child(child: &mut tokio::process::Child) -> Result<ChildOutcome> {
    let status = child
        .wait()
        .await
        .context("Failed to wait for command process")?;
    Ok(ChildOutcome::Exited(status))
}

pub(crate) fn map_spawn_error(error: std::io::Error, command: &str) -> anyhow::Error {
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

pub(crate) fn status_exit_code(status: &std::process::ExitStatus) -> i32 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sccache_backend_env_matching_is_backend_focused() {
        assert!(should_clear_sccache_backend_env_var("SCCACHE_BUCKET"));
        assert!(should_clear_sccache_backend_env_var(
            "SCCACHE_WEBDAV_ENDPOINT"
        ));
        assert!(should_clear_sccache_backend_env_var(
            "ACTIONS_RUNTIME_TOKEN"
        ));
        assert!(!should_clear_sccache_backend_env_var(
            "SCCACHE_IDLE_TIMEOUT"
        ));
        assert!(!should_clear_sccache_backend_env_var("SCCACHE_DIR"));
        assert!(!should_clear_sccache_backend_env_var("RUSTC_WRAPPER"));
    }

    #[test]
    fn inherited_sccache_backend_env_vars_filters_and_deduplicates() {
        let env_vars = inherited_sccache_backend_env_vars_from([
            OsString::from("SCCACHE_BUCKET"),
            OsString::from("SCCACHE_WEBDAV_ENDPOINT"),
            OsString::from("SCCACHE_IDLE_TIMEOUT"),
            OsString::from("SCCACHE_BUCKET"),
        ]);

        assert_eq!(
            env_vars,
            vec![
                "SCCACHE_BUCKET".to_string(),
                "SCCACHE_WEBDAV_ENDPOINT".to_string()
            ]
        );
    }
}

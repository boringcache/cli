use anyhow::Result;

use super::{AdapterCommandOptions, AdapterRunner};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "bazel",
    inject_proxy_env: super::no_extra_proxy_env,
    prepare_command,
};

fn prepare_command(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    options: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    let Some(context) = proxy_context else {
        return Ok(command.to_vec());
    };

    let injected = default_remote_cache_args(context, options)
        .into_iter()
        .filter(|arg| should_inject_default_arg(command, arg))
        .collect::<Vec<_>>();
    if injected.is_empty() {
        return Ok(command.to_vec());
    }

    let mut prepared = command.to_vec();
    let insert_at = bazel_insert_at(command);
    prepared.splice(insert_at..insert_at, injected);
    Ok(prepared)
}

fn bazel_insert_at(command: &[String]) -> usize {
    command
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, arg)| !arg.starts_with('-'))
        .map(|(index, _)| index + 1)
        .unwrap_or(command.len())
}

fn has_option(command: &[String], name: &str) -> bool {
    command
        .iter()
        .any(|arg| arg == name || arg.starts_with(&format!("{name}=")))
}

fn has_upload_flag(command: &[String]) -> bool {
    command.iter().any(|arg| {
        arg == "--remote_upload_local_results"
            || arg == "--noremote_upload_local_results"
            || arg.starts_with("--remote_upload_local_results=")
    })
}

fn has_remote_download_setting(command: &[String]) -> bool {
    command.iter().any(|arg| {
        arg == "--remote_download_minimal"
            || arg == "--noremote_download_minimal"
            || arg == "--remote_download_toplevel"
            || arg == "--noremote_download_toplevel"
            || arg.starts_with("--remote_download_outputs=")
    })
}

pub(super) fn default_remote_cache_args(
    context: &proxy::ProxyContext,
    options: &AdapterCommandOptions,
) -> Vec<String> {
    vec![
        format!("--remote_cache={}", context.endpoint()),
        format!("--remote_upload_local_results={}", !options.read_only),
        "--remote_cache_async=false".to_string(),
        "--remote_download_minimal".to_string(),
        format!("--remote_max_connections={}", remote_max_connections()),
    ]
}

fn should_inject_default_arg(command: &[String], arg: &str) -> bool {
    let option = arg.split_once('=').map(|(name, _)| name).unwrap_or(arg);
    match option {
        "--remote_upload_local_results" => !has_upload_flag(command),
        "--remote_download_minimal" => !has_remote_download_setting(command),
        "--remote_cache" | "--remote_cache_async" | "--remote_max_connections" => {
            !has_option(command, option)
        }
        _ => true,
    }
}

pub(super) fn remote_max_connections() -> u16 {
    std::env::var("BORINGCACHE_BAZEL_REMOTE_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> proxy::ProxyContext {
        proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        }
    }

    fn options(read_only: bool) -> AdapterCommandOptions {
        AdapterCommandOptions {
            cache_ref_tag: "buildcache".to_string(),
            cache_mode: "max".to_string(),
            read_only,
            docker_oci_cache: None,
            sccache_key_prefix: None,
            gradle_home: None,
            node_package_manager_env: Default::default(),
        }
    }

    #[test]
    fn bazel_prepare_command_injects_remote_cache_flags() {
        let command = prepare_command(
            &[
                "bazel".to_string(),
                "--bazelrc=.bazelrc".to_string(),
                "build".to_string(),
                "//...".to_string(),
            ],
            Some(&context()),
            &options(false),
        )
        .unwrap();

        assert_eq!(command[0], "bazel");
        assert_eq!(command[1], "--bazelrc=.bazelrc");
        assert_eq!(command[2], "build");
        assert_eq!(command[3], "--remote_cache=http://127.0.0.1:5000");
        assert_eq!(command[4], "--remote_upload_local_results=true");
        assert_eq!(command[5], "--remote_cache_async=false");
        assert_eq!(command[6], "--remote_download_minimal");
        assert_eq!(command[7], "--remote_max_connections=64");
    }

    #[test]
    fn bazel_prepare_command_preserves_explicit_cache_flags() {
        let command = prepare_command(
            &[
                "bazel".to_string(),
                "build".to_string(),
                "--remote_cache=http://cache.example".to_string(),
                "--noremote_upload_local_results".to_string(),
                "//...".to_string(),
            ],
            Some(&context()),
            &options(false),
        )
        .unwrap();

        assert!(command.contains(&"--remote_cache=http://cache.example".to_string()));
        assert!(command.contains(&"--noremote_upload_local_results".to_string()));
        assert!(command.contains(&"--remote_cache_async=false".to_string()));
        assert!(command.contains(&"--remote_download_minimal".to_string()));
        assert!(command.contains(&"--remote_max_connections=64".to_string()));
    }

    #[test]
    fn bazel_prepare_command_uses_read_only_upload_setting() {
        let command = prepare_command(
            &["bazel".to_string(), "test".to_string(), "//...".to_string()],
            Some(&context()),
            &options(true),
        )
        .unwrap();

        assert!(
            command
                .iter()
                .any(|arg| arg == "--remote_upload_local_results=false")
        );
    }
}

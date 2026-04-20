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

    let mut injected = Vec::new();
    if !has_option(command, "--remote_cache") {
        injected.push(format!("--remote_cache={}", context.endpoint()));
    }
    if !has_upload_flag(command) {
        injected.push(format!(
            "--remote_upload_local_results={}",
            !options.read_only
        ));
    }
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
            sccache_key_prefix: None,
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

        assert_eq!(
            command,
            vec![
                "bazel".to_string(),
                "build".to_string(),
                "--remote_cache=http://cache.example".to_string(),
                "--noremote_upload_local_results".to_string(),
                "//...".to_string(),
            ]
        );
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

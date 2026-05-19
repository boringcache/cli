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
    let mut args = vec![
        format!("--remote_cache={}", context.endpoint()),
        format!("--remote_upload_local_results={}", !options.read_only),
        "--remote_cache_async=false".to_string(),
        "--remote_download_minimal".to_string(),
        format!("--remote_max_connections={}", remote_max_connections()),
    ];
    args.extend(stable_host_env_args());
    args
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

fn stable_host_env_args() -> Vec<String> {
    if stable_host_env_disabled() {
        return Vec::new();
    }

    let Some(stable_path) = stable_host_path() else {
        return Vec::new();
    };

    let mut args = vec![
        "--incompatible_strict_action_env".to_string(),
        format!("--action_env=PATH={stable_path}"),
        format!("--host_action_env=PATH={stable_path}"),
        format!("--repo_env=PATH={stable_path}"),
    ];

    args.extend(stable_toolchain_env_args(&stable_path));
    args
}

fn stable_host_env_disabled() -> bool {
    std::env::var("BORINGCACHE_BAZEL_STABLE_HOST_ENV")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "no"
            )
        })
        .unwrap_or(false)
}

fn stable_host_path() -> Option<String> {
    let configured = std::env::var("BORINGCACHE_BAZEL_STABLE_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    configured.or_else(default_stable_host_path)
}

#[cfg(target_os = "linux")]
fn default_stable_host_path() -> Option<String> {
    Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string())
}

#[cfg(target_os = "macos")]
fn default_stable_host_path() -> Option<String> {
    Some("/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_stable_host_path() -> Option<String> {
    None
}

fn stable_toolchain_env_args(stable_path: &str) -> Vec<String> {
    let mut args = Vec::new();
    for (name, env_name, candidates) in stable_toolchain_candidates() {
        let resolved = std::env::var(env_name)
            .ok()
            .and_then(|value| stable_command_path(&value, stable_path))
            .or_else(|| first_stable_command_path(candidates, stable_path));
        if let Some(path) = resolved {
            args.push(format!("--repo_env={name}={path}"));
        }
    }
    args
}

#[cfg(target_os = "linux")]
fn stable_toolchain_candidates() -> Vec<(&'static str, &'static str, &'static [&'static str])> {
    vec![
        ("CC", "CC", &["gcc", "cc", "clang"]),
        ("CXX", "CXX", &["g++", "c++", "clang++"]),
        ("LD", "LD", &["ld"]),
    ]
}

#[cfg(target_os = "macos")]
fn stable_toolchain_candidates() -> Vec<(&'static str, &'static str, &'static [&'static str])> {
    vec![
        ("CC", "CC", &["cc", "clang"]),
        ("CXX", "CXX", &["c++", "clang++"]),
    ]
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn stable_toolchain_candidates() -> Vec<(&'static str, &'static str, &'static [&'static str])> {
    Vec::new()
}

fn first_stable_command_path(candidates: &[&str], stable_path: &str) -> Option<String> {
    candidates
        .iter()
        .find_map(|candidate| stable_command_path(candidate, stable_path))
}

fn stable_command_path(command: &str, stable_path: &str) -> Option<String> {
    let command = command.trim();
    if command.is_empty()
        || command.contains(char::is_whitespace)
        || command.contains('/')
        || command.contains('\\')
    {
        let path = std::path::Path::new(command);
        return path.is_absolute().then(|| command.to_string());
    }

    std::env::split_paths(stable_path)
        .map(|directory| directory.join(command))
        .find(|path| path.is_file())
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;

    fn context() -> proxy::ProxyContext {
        proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        }
    }

    fn options(read_only: bool) -> AdapterCommandOptions {
        AdapterCommandOptions {
            buildkit_cache_tag: "buildcache".to_string(),
            cache_mode: "max".to_string(),
            read_only,
            docker_oci_cache: None,
            sccache_key_prefix: None,
            gradle_home: None,
            node_package_manager_env: Default::default(),
            skip_actions: Vec::new(),
        }
    }

    #[test]
    fn bazel_prepare_command_injects_remote_cache_flags() {
        let _guard = stable_host_env_disabled_guard();
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
        let _guard = stable_host_env_disabled_guard();
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
        let _guard = stable_host_env_disabled_guard();
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

    #[test]
    fn bazel_default_args_pin_stable_host_path_for_cache_keys() {
        let _guard = test_env::lock();
        test_env::set_var(
            "BORINGCACHE_BAZEL_STABLE_PATH",
            "/usr/local/bin:/usr/bin:/bin",
        );
        test_env::remove_var("BORINGCACHE_BAZEL_STABLE_HOST_ENV");

        let args = default_remote_cache_args(&context(), &options(false));

        assert!(args.contains(&"--incompatible_strict_action_env".to_string()));
        assert!(args.contains(&"--action_env=PATH=/usr/local/bin:/usr/bin:/bin".to_string()));
        assert!(args.contains(&"--host_action_env=PATH=/usr/local/bin:/usr/bin:/bin".to_string()));
        assert!(args.contains(&"--repo_env=PATH=/usr/local/bin:/usr/bin:/bin".to_string()));
    }

    #[test]
    fn bazel_stable_host_env_can_be_disabled() {
        let _guard = stable_host_env_disabled_guard();

        let args = default_remote_cache_args(&context(), &options(false));

        assert!(!args.iter().any(|arg| arg.contains("action_env=PATH")));
        assert!(!args.iter().any(|arg| arg.contains("repo_env=PATH")));
    }

    fn stable_host_env_disabled_guard() -> test_env::Guard {
        let guard = test_env::lock();
        test_env::set_var("BORINGCACHE_BAZEL_STABLE_HOST_ENV", "0");
        test_env::remove_var("BORINGCACHE_BAZEL_STABLE_PATH");
        guard
    }
}

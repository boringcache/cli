use anyhow::Result;

use super::{AdapterCommandOptions, AdapterRunner, no_extra_proxy_env};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "docker",
    inject_proxy_env: no_extra_proxy_env,
    prepare_command,
};

pub(super) fn validate_cache_mode(value: &str) -> Result<()> {
    if matches!(value, "max" | "min") {
        Ok(())
    } else {
        anyhow::bail!("Invalid --cache-mode '{value}'. Expected 'max' or 'min'.");
    }
}

fn prepare_command(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    options: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    inject_docker_cache_flags(
        command,
        proxy_context,
        &options.cache_ref_tag,
        &options.cache_mode,
        options.read_only,
    )
}

fn inject_docker_cache_flags(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    cache_ref_tag: &str,
    cache_mode: &str,
    read_only: bool,
) -> Result<Vec<String>> {
    if proxy_context.is_none() {
        return Ok(command.to_vec());
    }

    if command.len() < 4
        || command[0] != "docker"
        || command[1] != "buildx"
        || command[2] != "build"
    {
        anyhow::bail!(
            "`boringcache docker` expects `docker buildx build ...`. Pass the docker buildx command after --."
        );
    }

    if command
        .iter()
        .any(|arg| arg == "--cache-from" || arg.starts_with("--cache-from="))
        || command
            .iter()
            .any(|arg| arg == "--cache-to" || arg.starts_with("--cache-to="))
    {
        anyhow::bail!(
            "Do not pass --cache-from/--cache-to to `boringcache docker`; use --cache-ref-tag and --cache-mode instead."
        );
    }

    let context = proxy_context.expect("checked above");
    let registry_ref = format!(
        "type=registry,ref={}:{}/cache:{}",
        context.endpoint_host, context.port, cache_ref_tag
    );
    let mut prepared = command.to_vec();
    let insert_at = prepared.len() - 1;
    prepared.insert(insert_at, format!("--cache-from={registry_ref}"));
    if !read_only {
        prepared.insert(
            insert_at + 1,
            format!("--cache-to={registry_ref},mode={cache_mode}"),
        );
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_cache_flags_insert_before_context() {
        let context = proxy::ProxyContext {
            endpoint_host: "host.docker.internal".to_string(),
            port: 5000,
            cache_ref: "{CACHE_REF}".to_string(),
        };

        let command = inject_docker_cache_flags(
            &[
                "docker".to_string(),
                "buildx".to_string(),
                "build".to_string(),
                "-t".to_string(),
                "ghcr.io/acme/app:latest".to_string(),
                "--push".to_string(),
                ".".to_string(),
            ],
            Some(&context),
            "buildcache",
            "max",
            false,
        )
        .unwrap();

        assert_eq!(command.last().map(String::as_str), Some("."));
        assert!(command.iter().any(|arg| arg
            == "--cache-from=type=registry,ref=host.docker.internal:5000/cache:buildcache"));
        assert!(command.iter().any(|arg| arg
            == "--cache-to=type=registry,ref=host.docker.internal:5000/cache:buildcache,mode=max"));
    }

    #[test]
    fn docker_cache_flags_are_read_only_when_requested() {
        let context = proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "{CACHE_REF}".to_string(),
        };

        let command = inject_docker_cache_flags(
            &[
                "docker".to_string(),
                "buildx".to_string(),
                "build".to_string(),
                ".".to_string(),
            ],
            Some(&context),
            "buildcache",
            "max",
            true,
        )
        .unwrap();

        assert!(
            command
                .iter()
                .any(|arg| arg == "--cache-from=type=registry,ref=127.0.0.1:5000/cache:buildcache")
        );
        assert!(!command.iter().any(|arg| arg.starts_with("--cache-to=")));
    }
}

use anyhow::Result;
use serde::Serialize;

use super::{AdapterCommandOptions, AdapterRunner, no_extra_proxy_env};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "docker",
    inject_proxy_env: no_extra_proxy_env,
    prepare_command,
};

const DEFAULT_CACHE_REF_TAG: &str = "buildcache";

#[derive(Debug, Clone, Serialize)]
pub(super) struct OciCachePlan {
    pub registry_ref: String,
    pub cache_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_to: Option<String>,
    pub ref_tag: String,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedDockerPlan {
    pub oci_cache: OciCachePlan,
}

pub(super) fn validate_cache_mode(value: &str) -> Result<()> {
    if matches!(value, "max" | "min") {
        Ok(())
    } else {
        anyhow::bail!("Invalid --cache-mode '{value}'. Expected 'max' or 'min'.");
    }
}

pub(super) fn resolve_docker_plan(
    raw_tag: &str,
    explicit_cache_ref_tag: Option<&str>,
    endpoint_host: &str,
    port: u16,
    cache_mode: &str,
    read_only: bool,
) -> Result<ResolvedDockerPlan> {
    let tag_input = raw_tag.trim();
    if tag_input.is_empty() {
        anyhow::bail!("Missing proxy tag.");
    }
    if tag_input.contains('@') {
        anyhow::bail!(
            "Unsupported --tag '{tag_input}'. Use a human-readable cache tag, not a digest reference."
        );
    }
    if tag_input.contains(':') {
        anyhow::bail!(
            "Unsupported --tag '{tag_input}'. Use --tag for the proxy cache tag and --cache-ref-tag for the OCI cache tag."
        );
    }

    let explicit_ref_tag = trim_non_empty(explicit_cache_ref_tag);
    let ref_tag = validate_cache_ref_tag(explicit_ref_tag.unwrap_or(DEFAULT_CACHE_REF_TAG))?;

    let registry_ref = format!("{endpoint_host}:{port}/cache:{ref_tag}");
    let cache_from = format!("type=registry,ref={registry_ref}");
    let cache_to = if read_only {
        None
    } else {
        Some(format!("{cache_from},mode={cache_mode}"))
    };

    Ok(ResolvedDockerPlan {
        oci_cache: OciCachePlan {
            registry_ref,
            cache_from,
            cache_to,
            ref_tag,
        },
    })
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

fn validate_cache_ref_tag(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Invalid --cache-ref-tag ''. Expected an OCI tag such as 'buildcache'.");
    }

    if !trimmed.chars().enumerate().all(|(index, ch)| {
        if index == 0 {
            ch.is_ascii_alphanumeric() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')
        }
    }) || trimmed.len() > 128
    {
        anyhow::bail!(
            "Invalid --cache-ref-tag '{value}'. Expected an OCI tag such as 'buildcache' or 'cache-main'."
        );
    }

    Ok(trimmed.to_string())
}

fn trim_non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
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

    #[test]
    fn resolve_docker_plan_rejects_embedded_ref_tag_syntax() {
        let error = resolve_docker_plan(
            "docker-main:cache-main",
            None,
            "127.0.0.1",
            5000,
            "max",
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains(
            "Use --tag for the proxy cache tag and --cache-ref-tag for the OCI cache tag"
        ));
    }
}

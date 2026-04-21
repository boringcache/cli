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
    #[serde(skip)]
    pub cache_from_ref_tags: Vec<String>,
    pub cache_from_refs: Vec<String>,
    pub cache_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_to: Option<String>,
    pub ref_tag: String,
    pub cache_to_ref_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable_run_ref_tag: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub promotion_ref_tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedDockerPlan {
    pub oci_cache: OciCachePlan,
}

pub(super) struct ResolveDockerPlanInput<'a> {
    pub raw_tag: &'a str,
    pub explicit_cache_ref_tag: Option<&'a str>,
    pub explicit_cache_run_ref_tag: Option<&'a str>,
    pub explicit_cache_from_ref_tags: &'a [String],
    pub explicit_cache_promote_ref_tags: &'a [String],
    pub endpoint_host: &'a str,
    pub port: u16,
    pub cache_mode: &'a str,
    pub read_only: bool,
}

pub(super) fn validate_cache_mode(value: &str) -> Result<()> {
    if matches!(value, "max" | "min") {
        Ok(())
    } else {
        anyhow::bail!("Invalid --cache-mode '{value}'. Expected 'max' or 'min'.");
    }
}

pub(super) fn resolve_docker_plan(input: ResolveDockerPlanInput<'_>) -> Result<ResolvedDockerPlan> {
    let ResolveDockerPlanInput {
        raw_tag,
        explicit_cache_ref_tag,
        explicit_cache_run_ref_tag,
        explicit_cache_from_ref_tags,
        explicit_cache_promote_ref_tags,
        endpoint_host,
        port,
        cache_mode,
        read_only,
    } = input;

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
    let immutable_run_ref_tag = trim_non_empty(explicit_cache_run_ref_tag)
        .map(validate_cache_ref_tag)
        .transpose()?;
    let cache_from_ref_tags = normalize_ref_tag_list(explicit_cache_from_ref_tags)?;
    let promotion_ref_tags = normalize_ref_tag_list(explicit_cache_promote_ref_tags)?;

    let import_ref_tags = if cache_from_ref_tags.is_empty() {
        vec![ref_tag.clone()]
    } else {
        cache_from_ref_tags
    };
    let cache_to_ref_tag = if read_only {
        None
    } else {
        Some(
            immutable_run_ref_tag
                .clone()
                .unwrap_or_else(|| ref_tag.clone()),
        )
    };
    let effective_promotion_ref_tags = if read_only || immutable_run_ref_tag.is_none() {
        Vec::new()
    } else if promotion_ref_tags.is_empty() {
        vec![ref_tag.clone()]
    } else {
        promotion_ref_tags
    };

    let cache_from_refs = import_ref_tags
        .iter()
        .map(|tag| format!("type=registry,ref={endpoint_host}:{port}/cache:{tag}"))
        .collect::<Vec<_>>();
    let cache_from = cache_from_refs
        .first()
        .cloned()
        .expect("docker cache imports always include at least one ref");
    let cache_to = cache_to_ref_tag.as_deref().map(|cache_to_ref_tag| {
        format!(
            "type=registry,ref={endpoint_host}:{port}/cache:{cache_to_ref_tag},mode={cache_mode}"
        )
    });
    let registry_ref = cache_to_ref_tag
        .as_ref()
        .or_else(|| import_ref_tags.first())
        .map(|tag| format!("{endpoint_host}:{port}/cache:{tag}"))
        .expect("docker cache plan requires an import or export ref");

    Ok(ResolvedDockerPlan {
        oci_cache: OciCachePlan {
            registry_ref,
            cache_from_ref_tags: import_ref_tags,
            cache_from_refs,
            cache_from,
            cache_to,
            ref_tag,
            cache_to_ref_tag,
            immutable_run_ref_tag,
            promotion_ref_tags: effective_promotion_ref_tags,
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
        options.docker_oci_cache.as_ref(),
    )
}

fn inject_docker_cache_flags(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    cache_ref_tag: &str,
    cache_mode: &str,
    read_only: bool,
    oci_cache: Option<&OciCachePlan>,
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
    let fallback_cache_from = format!(
        "type=registry,ref={}:{}/cache:{}",
        context.endpoint_host, context.port, cache_ref_tag
    );
    let cache_from_refs = oci_cache
        .map(|plan| plan.cache_from_refs.as_slice())
        .filter(|refs| !refs.is_empty())
        .unwrap_or(std::slice::from_ref(&fallback_cache_from));
    let mut prepared = command.to_vec();
    let insert_at = prepared.len() - 1;
    for (offset, cache_from) in cache_from_refs.iter().enumerate() {
        prepared.insert(insert_at + offset, format!("--cache-from={cache_from}"));
    }
    if !read_only {
        let cache_to = oci_cache
            .and_then(|plan| plan.cache_to.as_deref())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{fallback_cache_from},mode={cache_mode}"));
        prepared.insert(
            insert_at + cache_from_refs.len(),
            format!("--cache-to={cache_to}"),
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

fn normalize_ref_tag_list(values: &[String]) -> Result<Vec<String>> {
    let mut tags = Vec::new();
    for value in values.iter().flat_map(|value| value.split(',')) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tag = validate_cache_ref_tag(trimmed)?;
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    Ok(tags)
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
            None,
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
            None,
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
        let error = resolve_docker_plan(ResolveDockerPlanInput {
            raw_tag: "docker-main:cache-main",
            explicit_cache_ref_tag: None,
            explicit_cache_run_ref_tag: None,
            explicit_cache_from_ref_tags: &[],
            explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
        })
        .unwrap_err();

        assert!(error.to_string().contains(
            "Use --tag for the proxy cache tag and --cache-ref-tag for the OCI cache tag"
        ));
    }
}

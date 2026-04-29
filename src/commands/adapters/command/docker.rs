use anyhow::Result;
use serde::Serialize;

use super::{AdapterCommandOptions, AdapterRunner, no_extra_proxy_env};
use crate::ci_detection::{CiRunContext, CiSourceRefType};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "docker",
    inject_proxy_env: no_extra_proxy_env,
    prepare_command,
};

pub(super) const BUILDKIT_RUNNER: AdapterRunner = AdapterRunner {
    name: "buildkit",
    inject_proxy_env: no_extra_proxy_env,
    prepare_command: prepare_buildkit_command,
};

const DEFAULT_CACHE_REF_TAG: &str = "buildcache";

#[derive(Debug, Clone, Serialize)]
pub(super) struct OciCachePlan {
    pub registry_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_metadata: Option<CiRunContext>,
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
    pub run_context: Option<CiRunContext>,
}

#[derive(Debug, Clone)]
struct DerivedCacheRefs {
    run_ref_tag: String,
    import_ref_tags: Vec<String>,
    promotion_ref_tags: Vec<String>,
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
        run_context,
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
    let explicit_immutable_run_ref_tag = trim_non_empty(explicit_cache_run_ref_tag)
        .map(validate_cache_ref_tag)
        .transpose()?;
    let cache_from_ref_tags = normalize_ref_tag_list(explicit_cache_from_ref_tags)?;
    let promotion_ref_tags = normalize_ref_tag_list(explicit_cache_promote_ref_tags)?;
    let derived_cache_refs = run_context
        .as_ref()
        .map(|context| derive_cache_refs(context, &ref_tag))
        .transpose()?;
    let immutable_run_ref_tag = explicit_immutable_run_ref_tag.clone().or_else(|| {
        derived_cache_refs
            .as_ref()
            .map(|derived| derived.run_ref_tag.clone())
    });

    let import_ref_tags = if cache_from_ref_tags.is_empty() {
        derived_cache_refs
            .as_ref()
            .map(|derived| derived.import_ref_tags.clone())
            .unwrap_or_else(|| vec![ref_tag.clone()])
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
    } else if !promotion_ref_tags.is_empty() {
        promotion_ref_tags
    } else if let Some(derived) = &derived_cache_refs {
        derived.promotion_ref_tags.clone()
    } else {
        vec![ref_tag.clone()]
    };

    let cache_from_refs = import_ref_tags
        .iter()
        .map(|tag| docker_cache_import_spec(&format!("{endpoint_host}:{port}/cache:{tag}")))
        .collect::<Vec<_>>();
    let cache_from = cache_from_refs
        .first()
        .cloned()
        .expect("docker cache imports always include at least one ref");
    let cache_to = cache_to_ref_tag.as_deref().map(|cache_to_ref_tag| {
        docker_cache_export_spec(
            &format!("{endpoint_host}:{port}/cache:{cache_to_ref_tag}"),
            cache_mode,
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
            run_metadata: run_context,
        },
    })
}

fn derive_cache_refs(context: &CiRunContext, fallback_ref_tag: &str) -> Result<DerivedCacheRefs> {
    let run_ref_tag = validate_cache_ref_tag(&run_ref_tag(context)?)?;
    let mut import_ref_tags = Vec::new();
    let mut promotion_ref_tags = Vec::new();

    match context.source_ref_type {
        CiSourceRefType::PullRequest => {
            if let Some(pr_number) = context.pull_request_number {
                push_tag(&mut import_ref_tags, pr_alias(pr_number)?);
                push_tag(&mut promotion_ref_tags, pr_alias(pr_number)?);
            }
            if let Some(head_ref) = context
                .head_ref_name
                .as_deref()
                .or(context.source_ref_name.as_deref())
            {
                push_tag(&mut import_ref_tags, branch_alias(head_ref)?);
            }
            push_tag(&mut import_ref_tags, "default".to_string());
        }
        CiSourceRefType::Branch => {
            if let Some(branch) = context.source_ref_name.as_deref() {
                let branch_alias = branch_alias(branch)?;
                push_tag(&mut import_ref_tags, branch_alias.clone());
                push_tag(&mut promotion_ref_tags, branch_alias);
                if is_default_branch(branch, context.default_branch.as_deref()) {
                    push_tag(&mut promotion_ref_tags, "default".to_string());
                }
            }
            push_tag(&mut import_ref_tags, "default".to_string());
        }
        CiSourceRefType::Tag | CiSourceRefType::Other => {
            push_tag(&mut import_ref_tags, "default".to_string());
        }
    }

    push_tag(&mut import_ref_tags, fallback_ref_tag.to_string());
    if context.source_ref_type != CiSourceRefType::PullRequest {
        push_tag(&mut promotion_ref_tags, fallback_ref_tag.to_string());
    }
    let import_ref_tags = validate_ref_tag_list(import_ref_tags)?;
    let promotion_ref_tags = validate_ref_tag_list(promotion_ref_tags)?;

    Ok(DerivedCacheRefs {
        run_ref_tag,
        import_ref_tags,
        promotion_ref_tags,
    })
}

fn run_ref_tag(context: &CiRunContext) -> Result<String> {
    let provider = provider_tag_component(&context.provider);
    let run_uid = tag_component(&context.run_uid, 96);
    let candidate = if let Some(attempt) = context.run_attempt.as_deref() {
        let attempt = tag_component(attempt, 24);
        format!("run-{provider}-{run_uid}-attempt-{attempt}")
    } else {
        format!("run-{provider}-{run_uid}")
    };

    shorten_tag(candidate)
}

fn provider_tag_component(provider: &str) -> String {
    match provider.trim().to_ascii_lowercase().as_str() {
        "github-actions" | "github" | "gha" => "gha".to_string(),
        other => tag_component(other, 24),
    }
}

fn branch_alias(branch: &str) -> Result<String> {
    prefixed_tag("branch", branch)
}

fn pr_alias(number: u32) -> Result<String> {
    validate_cache_ref_tag(&format!("pr-{number}"))
}

fn prefixed_tag(prefix: &str, value: &str) -> Result<String> {
    let available = 128usize.saturating_sub(prefix.len() + 1);
    validate_cache_ref_tag(&format!("{prefix}-{}", tag_component(value, available)))
}

fn validate_ref_tag_list(values: Vec<String>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| validate_cache_ref_tag(&value))
        .collect()
}

fn tag_component(value: &str, max_len: usize) -> String {
    let mut component = String::with_capacity(value.len().min(max_len));
    let mut last_was_separator = false;

    for ch in value.trim().chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else if matches!(ch, '_' | '.' | '-') {
            ch
        } else {
            '-'
        };

        if matches!(mapped, '-' | '.') {
            if last_was_separator {
                continue;
            }
            last_was_separator = true;
        } else {
            last_was_separator = false;
        }

        component.push(mapped);
    }

    let component = component
        .trim_matches(|ch| matches!(ch, '-' | '.'))
        .to_string();
    let component = if component.is_empty() {
        "unknown".to_string()
    } else {
        component
    };

    if component.len() <= max_len {
        component
    } else {
        shorten_component(&component, max_len)
    }
}

fn shorten_component(component: &str, max_len: usize) -> String {
    let hash = crate::cas_oci::sha256_hex(component.as_bytes());
    let hash_len = 12usize.min(hash.len());
    let prefix_len = max_len.saturating_sub(hash_len + 1);
    if prefix_len == 0 {
        hash[..max_len.min(hash.len())].to_string()
    } else {
        format!("{}-{}", &component[..prefix_len], &hash[..hash_len])
    }
}

fn shorten_tag(candidate: String) -> Result<String> {
    if candidate.len() <= 128 {
        return validate_cache_ref_tag(&candidate);
    }

    let hash = crate::cas_oci::sha256_hex(candidate.as_bytes());
    let keep = 128usize.saturating_sub(13);
    validate_cache_ref_tag(&format!("{}-{}", &candidate[..keep], &hash[..12]))
}

fn push_tag(tags: &mut Vec<String>, tag: String) {
    if !tags.contains(&tag) {
        tags.push(tag);
    }
}

fn is_default_branch(branch: &str, default_branch: Option<&str>) -> bool {
    let branch = tag_component(branch, 128);
    if let Some(default_branch) = default_branch {
        branch == tag_component(default_branch, 128)
    } else {
        matches!(branch.as_str(), "main" | "master")
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
        options.docker_oci_cache.as_ref(),
    )
}

fn prepare_buildkit_command(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    options: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    inject_buildkit_cache_flags(
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
    let fallback_registry_ref = format!(
        "{}:{}/cache:{}",
        context.endpoint_host, context.port, cache_ref_tag
    );
    let fallback_cache_from = docker_cache_import_spec(&fallback_registry_ref);
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
            .unwrap_or_else(|| docker_cache_export_spec(&fallback_registry_ref, cache_mode));
        prepared.insert(
            insert_at + cache_from_refs.len(),
            format!("--cache-to={cache_to}"),
        );
    }
    Ok(prepared)
}

fn inject_buildkit_cache_flags(
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

    if command.len() < 2 || command[0] != "buildctl" || !command.iter().any(|arg| arg == "build") {
        anyhow::bail!(
            "`boringcache buildkit` expects `buildctl build ...`. Pass the buildctl command after --."
        );
    }

    if command
        .iter()
        .any(|arg| arg == "--import-cache" || arg.starts_with("--import-cache="))
        || command
            .iter()
            .any(|arg| arg == "--export-cache" || arg.starts_with("--export-cache="))
    {
        anyhow::bail!(
            "Do not pass --import-cache/--export-cache to `boringcache buildkit`; use --cache-ref-tag and --cache-mode instead."
        );
    }

    let context = proxy_context.expect("checked above");
    let fallback_registry_ref = format!(
        "{}:{}/cache:{}",
        context.endpoint_host, context.port, cache_ref_tag
    );
    let fallback_cache_from = docker_cache_import_spec(&fallback_registry_ref);
    let cache_from_refs = oci_cache
        .map(|plan| plan.cache_from_refs.as_slice())
        .filter(|refs| !refs.is_empty())
        .unwrap_or(std::slice::from_ref(&fallback_cache_from));
    let mut prepared = command.to_vec();
    for cache_from in cache_from_refs {
        prepared.push("--import-cache".to_string());
        prepared.push(cache_from.clone());
    }
    if !read_only {
        let cache_to = oci_cache
            .and_then(|plan| plan.cache_to.as_deref())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| docker_cache_export_spec(&fallback_registry_ref, cache_mode));
        prepared.push("--export-cache".to_string());
        prepared.push(cache_to);
    }
    Ok(prepared)
}

fn docker_cache_import_spec(registry_ref: &str) -> String {
    format!("type=registry,ref={registry_ref},registry.insecure=true")
}

fn docker_cache_export_spec(registry_ref: &str, cache_mode: &str) -> String {
    format!("type=registry,ref={registry_ref},mode={cache_mode},registry.insecure=true")
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
            == "--cache-from=type=registry,ref=host.docker.internal:5000/cache:buildcache,registry.insecure=true"));
        assert!(command.iter().any(|arg| arg
            == "--cache-to=type=registry,ref=host.docker.internal:5000/cache:buildcache,mode=max,registry.insecure=true"));
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
                .any(|arg| arg == "--cache-from=type=registry,ref=127.0.0.1:5000/cache:buildcache,registry.insecure=true")
        );
        assert!(!command.iter().any(|arg| arg.starts_with("--cache-to=")));
    }

    #[test]
    fn buildkit_cache_flags_append_import_and_export_refs() {
        let context = proxy::ProxyContext {
            endpoint_host: "host.docker.internal".to_string(),
            port: 5000,
            cache_ref: "{CACHE_REF}".to_string(),
        };

        let command = inject_buildkit_cache_flags(
            &[
                "buildctl".to_string(),
                "--addr".to_string(),
                "tcp://buildkitd:1234".to_string(),
                "build".to_string(),
                "--frontend".to_string(),
                "dockerfile.v0".to_string(),
            ],
            Some(&context),
            "buildcache",
            "max",
            false,
            None,
        )
        .unwrap();

        assert_eq!(
            command[command.len() - 4],
            "--import-cache",
            "import flag should be appended"
        );
        assert_eq!(
            command[command.len() - 3],
            "type=registry,ref=host.docker.internal:5000/cache:buildcache,registry.insecure=true"
        );
        assert_eq!(
            command[command.len() - 2],
            "--export-cache",
            "export flag should be appended"
        );
        assert_eq!(
            command[command.len() - 1],
            "type=registry,ref=host.docker.internal:5000/cache:buildcache,mode=max,registry.insecure=true"
        );
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
            run_context: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains(
            "Use --tag for the proxy cache tag and --cache-ref-tag for the OCI cache tag"
        ));
    }

    #[test]
    fn resolve_docker_plan_derives_branch_aliases_from_ci_run_context() {
        let plan = resolve_docker_plan(ResolveDockerPlanInput {
            raw_tag: "docker-main",
            explicit_cache_ref_tag: None,
            explicit_cache_run_ref_tag: None,
            explicit_cache_from_ref_tags: &[],
            explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: Some(CiRunContext {
                provider: "github-actions".to_string(),
                run_uid: "12345".to_string(),
                run_attempt: Some("1".to_string()),
                repository: Some("acme/widgets".to_string()),
                source_ref_type: CiSourceRefType::Branch,
                source_ref: Some("refs/heads/main".to_string()),
                source_ref_name: Some("main".to_string()),
                head_ref_name: None,
                base_ref_name: None,
                default_branch: Some("main".to_string()),
                pull_request_number: None,
                commit_sha: Some("abcdef".to_string()),
                run_started_at: Some("2026-04-21T10:00:00Z".to_string()),
            }),
        })
        .unwrap();

        assert_eq!(
            plan.oci_cache.immutable_run_ref_tag.as_deref(),
            Some("run-gha-12345-attempt-1")
        );
        assert_eq!(
            plan.oci_cache.cache_from_ref_tags,
            ["branch-main", "default", "buildcache"]
        );
        assert_eq!(
            plan.oci_cache.promotion_ref_tags,
            ["branch-main", "default", "buildcache"]
        );
    }

    #[test]
    fn resolve_docker_plan_keeps_pr_fallback_restore_only_by_default() {
        let plan = resolve_docker_plan(ResolveDockerPlanInput {
            raw_tag: "docker-main",
            explicit_cache_ref_tag: None,
            explicit_cache_run_ref_tag: None,
            explicit_cache_from_ref_tags: &[],
            explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: Some(CiRunContext {
                provider: "github-actions".to_string(),
                run_uid: "12345".to_string(),
                run_attempt: Some("1".to_string()),
                repository: Some("acme/widgets".to_string()),
                source_ref_type: CiSourceRefType::PullRequest,
                source_ref: Some("refs/pull/7/merge".to_string()),
                source_ref_name: Some("feature/cache".to_string()),
                head_ref_name: Some("feature/cache".to_string()),
                base_ref_name: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                pull_request_number: Some(7),
                commit_sha: Some("abcdef".to_string()),
                run_started_at: Some("2026-04-21T10:00:00Z".to_string()),
            }),
        })
        .unwrap();

        assert_eq!(
            plan.oci_cache.cache_from_ref_tags,
            ["pr-7", "branch-feature-cache", "default", "buildcache"]
        );
        assert_eq!(plan.oci_cache.promotion_ref_tags, ["pr-7"]);
    }

    #[test]
    fn resolve_docker_plan_keeps_explicit_alias_overrides() {
        let from_refs = vec!["manual-from".to_string()];
        let promote_refs = vec!["manual-promote".to_string()];
        let plan = resolve_docker_plan(ResolveDockerPlanInput {
            raw_tag: "docker-main",
            explicit_cache_ref_tag: None,
            explicit_cache_run_ref_tag: Some("manual-run"),
            explicit_cache_from_ref_tags: &from_refs,
            explicit_cache_promote_ref_tags: &promote_refs,
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: Some(CiRunContext {
                provider: "github-actions".to_string(),
                run_uid: "12345".to_string(),
                run_attempt: Some("1".to_string()),
                repository: None,
                source_ref_type: CiSourceRefType::PullRequest,
                source_ref: Some("refs/pull/7/merge".to_string()),
                source_ref_name: Some("feature/cache".to_string()),
                head_ref_name: Some("feature/cache".to_string()),
                base_ref_name: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                pull_request_number: Some(7),
                commit_sha: None,
                run_started_at: None,
            }),
        })
        .unwrap();

        assert_eq!(
            plan.oci_cache.immutable_run_ref_tag.as_deref(),
            Some("manual-run")
        );
        assert_eq!(plan.oci_cache.cache_from_ref_tags, ["manual-from"]);
        assert_eq!(plan.oci_cache.promotion_ref_tags, ["manual-promote"]);
    }
}

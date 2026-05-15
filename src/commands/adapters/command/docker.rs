use anyhow::Result;
use serde::Serialize;

use super::{AdapterCommandOptions, AdapterRunner, no_extra_proxy_env};
use crate::ci_detection::CiRunContext;
use crate::proxy;

const LEGACY_DOCKER_CACHE_REF_TAG_DEFAULT: &str = "buildcache";

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

#[derive(Debug, Clone, Serialize)]
pub(super) struct OciCachePlan {
    pub registry_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cache_from_tags: Vec<String>,
    pub cache_from_refs: Vec<String>,
    pub cache_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_to: Option<String>,
    pub cache_tag: String,
    pub cache_to_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_metadata: Option<CiRunContext>,
}

#[derive(Debug, Clone)]
pub(super) struct ResolvedDockerPlan {
    pub oci_cache: OciCachePlan,
}

pub(super) struct ResolveDockerPlanInput<'a> {
    pub human_cache_tag: &'a str,
    pub human_cache_restore_tags: &'a [String],
    pub legacy_explicit_cache_ref_tag: Option<&'a str>,
    pub legacy_explicit_cache_run_ref_tag: Option<&'a str>,
    pub legacy_explicit_cache_from_ref_tags: &'a [String],
    pub legacy_explicit_cache_promote_ref_tags: &'a [String],
    pub endpoint_host: &'a str,
    pub port: u16,
    pub cache_mode: &'a str,
    pub read_only: bool,
    pub run_context: Option<CiRunContext>,
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
        human_cache_tag,
        human_cache_restore_tags,
        legacy_explicit_cache_ref_tag,
        legacy_explicit_cache_run_ref_tag,
        legacy_explicit_cache_from_ref_tags,
        legacy_explicit_cache_promote_ref_tags,
        endpoint_host,
        port,
        cache_mode,
        read_only,
        run_context,
    } = input;

    let human_cache_tag = validate_human_oci_tag(human_cache_tag)?;
    if human_cache_tag.is_empty() {
        anyhow::bail!("Missing proxy tag.");
    }
    if human_cache_tag.contains('@') {
        anyhow::bail!(
            "Unsupported --tag '{human_cache_tag}'. Use a human-readable cache tag, not a digest reference."
        );
    }
    let unsupported_legacy_cache_ref_tag = trim_non_empty(legacy_explicit_cache_ref_tag)
        .is_some_and(|tag| tag != LEGACY_DOCKER_CACHE_REF_TAG_DEFAULT);
    if unsupported_legacy_cache_ref_tag
        || trim_non_empty(legacy_explicit_cache_run_ref_tag).is_some()
        || !legacy_explicit_cache_from_ref_tags.is_empty()
        || !legacy_explicit_cache_promote_ref_tags.is_empty()
    {
        anyhow::bail!(
            "Docker cache ref overrides are no longer needed. Use --tag to choose the cache tag."
        );
    }

    let import_cache_tags = validate_cache_tag_list(human_cache_restore_tags.to_vec())?;
    let cache_to_tag = if read_only {
        None
    } else {
        Some(human_cache_tag.clone())
    };
    let cache_from_refs = import_cache_tags
        .iter()
        .map(|tag| docker_cache_import_spec(&format!("{endpoint_host}:{port}/cache:{tag}")))
        .collect::<Vec<_>>();
    let cache_from = cache_from_refs
        .first()
        .cloned()
        .expect("docker cache imports always include at least one ref");
    let cache_to = cache_to_tag.as_deref().map(|cache_to_tag| {
        docker_cache_export_spec(
            &format!("{endpoint_host}:{port}/cache:{cache_to_tag}"),
            cache_mode,
        )
    });
    let registry_ref = cache_to_tag
        .as_ref()
        .or_else(|| import_cache_tags.first())
        .map(|tag| format!("{endpoint_host}:{port}/cache:{tag}"))
        .expect("docker cache plan requires an import or export ref");

    Ok(ResolvedDockerPlan {
        oci_cache: OciCachePlan {
            registry_ref,
            cache_from_tags: import_cache_tags,
            cache_from_refs,
            cache_from,
            cache_to,
            cache_tag: human_cache_tag,
            cache_to_tag,
            run_metadata: run_context,
        },
    })
}

fn validate_cache_tag_list(values: Vec<String>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| validate_human_oci_tag(&value))
        .collect()
}

fn prepare_command(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    options: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    inject_docker_cache_flags(
        command,
        proxy_context,
        &options.buildkit_cache_tag,
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
        &options.buildkit_cache_tag,
        &options.cache_mode,
        options.read_only,
        options.docker_oci_cache.as_ref(),
    )
}

fn inject_docker_cache_flags(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    buildkit_cache_tag: &str,
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
            "Do not pass --cache-from/--cache-to to `boringcache docker`; BoringCache injects cache refs from --tag and --cache-mode."
        );
    }

    let context = proxy_context.expect("checked above");
    let fallback_registry_ref = format!(
        "{}:{}/cache:{}",
        context.endpoint_host, context.port, buildkit_cache_tag
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
    buildkit_cache_tag: &str,
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
            "Do not pass --import-cache/--export-cache to `boringcache buildkit`; BoringCache injects cache refs from --tag and --cache-mode."
        );
    }

    let context = proxy_context.expect("checked above");
    let fallback_registry_ref = format!(
        "{}:{}/cache:{}",
        context.endpoint_host, context.port, buildkit_cache_tag
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
    // The registry ref is always the local proxy endpoint started for this
    // command, so BuildKit must use plain HTTP to reach it.
    format!("type=registry,ref={registry_ref},registry.insecure=true")
}

fn docker_cache_export_spec(registry_ref: &str, cache_mode: &str) -> String {
    // The registry ref is always the local proxy endpoint started for this
    // command, so BuildKit must use plain HTTP to reach it.
    format!("type=registry,ref={registry_ref},mode={cache_mode},registry.insecure=true")
}

fn validate_human_oci_tag(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Invalid --tag ''. Docker/BuildKit cache tags must also be valid OCI tags.");
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
            "Invalid --tag '{value}'. Docker/BuildKit cache tags must also be valid OCI tags such as 'docker-main' or 'cache-main'."
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
    fn resolve_docker_plan_rejects_non_oci_tag_human_cache_tag() {
        let restore_tags = vec!["docker-main:cache-main".to_string()];
        let error = resolve_docker_plan(ResolveDockerPlanInput {
            human_cache_tag: "docker-main:cache-main",
            human_cache_restore_tags: &restore_tags,
            legacy_explicit_cache_ref_tag: None,
            legacy_explicit_cache_run_ref_tag: None,
            legacy_explicit_cache_from_ref_tags: &[],
            legacy_explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: None,
        })
        .unwrap_err();

        assert!(error.to_string().contains("Invalid --tag"));
    }

    #[test]
    fn resolve_docker_plan_uses_resolved_human_tags() {
        let restore_tags = vec![
            "docker-main-branch-feature-x-ubuntu-24-x86_64".to_string(),
            "docker-main-ubuntu-24-x86_64".to_string(),
        ];
        let plan = resolve_docker_plan(ResolveDockerPlanInput {
            human_cache_tag: "docker-main-branch-feature-x-ubuntu-24-x86_64",
            human_cache_restore_tags: &restore_tags,
            legacy_explicit_cache_ref_tag: None,
            legacy_explicit_cache_run_ref_tag: None,
            legacy_explicit_cache_from_ref_tags: &[],
            legacy_explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: None,
        })
        .unwrap();

        assert_eq!(plan.oci_cache.cache_from_tags, restore_tags);
        assert_eq!(
            plan.oci_cache.cache_to_tag.as_deref(),
            Some("docker-main-branch-feature-x-ubuntu-24-x86_64")
        );
    }

    #[test]
    fn resolve_docker_plan_read_only_omits_export() {
        let restore_tags = vec![
            "docker-main-branch-release-1-ubuntu-24-x86_64".to_string(),
            "docker-main-ubuntu-24-x86_64".to_string(),
        ];
        let plan = resolve_docker_plan(ResolveDockerPlanInput {
            human_cache_tag: "docker-main-pr-7-ubuntu-24-x86_64",
            human_cache_restore_tags: &restore_tags,
            legacy_explicit_cache_ref_tag: None,
            legacy_explicit_cache_run_ref_tag: None,
            legacy_explicit_cache_from_ref_tags: &[],
            legacy_explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: true,
            run_context: None,
        })
        .unwrap();

        assert_eq!(plan.oci_cache.cache_from_tags, restore_tags);
        assert!(plan.oci_cache.cache_to.is_none());
        assert!(plan.oci_cache.cache_to_tag.is_none());
    }

    #[test]
    fn resolve_docker_plan_rejects_explicit_import_overrides() {
        let restore_tags = vec!["docker-main".to_string()];
        let from_refs = vec!["manual-human-from".to_string()];
        let error = resolve_docker_plan(ResolveDockerPlanInput {
            human_cache_tag: "docker-main",
            human_cache_restore_tags: &restore_tags,
            legacy_explicit_cache_ref_tag: None,
            legacy_explicit_cache_run_ref_tag: None,
            legacy_explicit_cache_from_ref_tags: &from_refs,
            legacy_explicit_cache_promote_ref_tags: &[],
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: None,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Use --tag to choose the cache tag")
        );
    }

    #[test]
    fn resolve_docker_plan_rejects_old_ref_overrides() {
        let restore_tags = vec!["docker-main".to_string()];
        let promote_refs = vec!["manual-promote".to_string()];
        let error = resolve_docker_plan(ResolveDockerPlanInput {
            human_cache_tag: "docker-main",
            human_cache_restore_tags: &restore_tags,
            legacy_explicit_cache_ref_tag: None,
            legacy_explicit_cache_run_ref_tag: Some("manual-run"),
            legacy_explicit_cache_from_ref_tags: &[],
            legacy_explicit_cache_promote_ref_tags: &promote_refs,
            endpoint_host: "127.0.0.1",
            port: 5000,
            cache_mode: "max",
            read_only: false,
            run_context: None,
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Use --tag to choose the cache tag")
        );
    }

    #[test]
    fn resolve_docker_plan_preserves_run_metadata_without_deriving_refs() {
        use crate::ci_detection::CiSourceRefType;

        let restore_tags = vec!["docker-main".to_string()];
        let plan = resolve_docker_plan(ResolveDockerPlanInput {
            human_cache_tag: "docker-main",
            human_cache_restore_tags: &restore_tags,
            legacy_explicit_cache_ref_tag: None,
            legacy_explicit_cache_run_ref_tag: None,
            legacy_explicit_cache_from_ref_tags: &[],
            legacy_explicit_cache_promote_ref_tags: &[],
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
            plan.oci_cache
                .run_metadata
                .as_ref()
                .map(|context| context.run_uid.as_str()),
            Some("12345")
        );
    }
}

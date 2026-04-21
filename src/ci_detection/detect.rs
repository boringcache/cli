use std::env;

use super::{CiContext, CiRunContext, CiSourceRefType};

const CI_INDICATORS: &[(&str, &str)] = &[
    ("GITHUB_ACTIONS", "github-actions"),
    ("GITLAB_CI", "gitlab-ci"),
    ("CIRCLECI", "circleci"),
    ("JENKINS_URL", "jenkins"),
    ("BUILDKITE", "buildkite"),
    ("TRAVIS", "travis-ci"),
    ("APPVEYOR", "appveyor"),
    ("AZURE_HTTP_USER_AGENT", "azure-devops"),
    ("TEAMCITY_VERSION", "teamcity"),
    ("BAMBOO_BUILD_KEY", "bamboo"),
    ("CODEBUILD_BUILD_ID", "aws-codebuild"),
    ("BITBUCKET_BUILD_NUMBER", "bitbucket-pipelines"),
    ("DRONE", "drone"),
    ("SEMAPHORE", "semaphore"),
    ("WERCKER", "wercker"),
    ("NETLIFY", "netlify"),
    ("VERCEL", "vercel"),
    ("RENDER", "render"),
    ("HEROKU_APP_ID", "heroku"),
];

impl CiContext {
    pub fn detect() -> Self {
        Self::new(
            detect_providers(),
            detect_os_tag(),
            detect_arch_tag(),
            detect_benchmark_mode(),
            detect_run_context(),
        )
    }
}

pub fn detect_ci_context() -> CiContext {
    CiContext::detect()
}

pub fn detect_ci_environment() -> String {
    detect_ci_context().label()
}

pub fn build_tags_string() -> String {
    detect_ci_context().tags().join(",")
}

fn detect_providers() -> Vec<&'static str> {
    let mut providers = Vec::new();
    for (env_var, name) in CI_INDICATORS {
        if env::var(env_var).is_ok() {
            providers.push(*name);
        }
    }

    if env::var("CI").is_ok() && providers.is_empty() {
        providers.push("generic-ci");
    }

    providers
}

fn detect_os_tag() -> Option<String> {
    env::var("RUNNER_OS")
        .or_else(|_| env::var("OS"))
        .ok()
        .map(|value| format!("os:{}", value.to_lowercase()))
}

fn detect_arch_tag() -> Option<String> {
    env::var("RUNNER_ARCH")
        .ok()
        .map(|value| format!("arch:{}", value.to_lowercase()))
}

fn detect_benchmark_mode() -> bool {
    env::var("BORINGCACHE_BENCHMARK_MODE").is_ok()
}

fn detect_run_context() -> Option<CiRunContext> {
    detect_provider_neutral_run_context().or_else(detect_github_actions_run_context)
}

fn detect_provider_neutral_run_context() -> Option<CiRunContext> {
    let provider = env_trimmed("BORINGCACHE_CI_PROVIDER")?;
    let run_uid = env_trimmed("BORINGCACHE_CI_RUN_ID")?;
    let source_ref_type = env_trimmed("BORINGCACHE_CI_REF_TYPE")
        .as_deref()
        .map(parse_source_ref_type)
        .unwrap_or(CiSourceRefType::Other);

    Some(CiRunContext {
        provider,
        run_uid,
        run_attempt: env_trimmed("BORINGCACHE_CI_RUN_ATTEMPT"),
        repository: env_trimmed("BORINGCACHE_CI_REPOSITORY"),
        source_ref_type,
        source_ref: env_trimmed("BORINGCACHE_CI_REF"),
        source_ref_name: env_trimmed("BORINGCACHE_CI_REF_NAME"),
        head_ref_name: env_trimmed("BORINGCACHE_CI_HEAD_REF"),
        base_ref_name: env_trimmed("BORINGCACHE_CI_BASE_REF"),
        default_branch: env_trimmed("BORINGCACHE_CI_DEFAULT_BRANCH"),
        pull_request_number: env_trimmed("BORINGCACHE_CI_PR_NUMBER")
            .and_then(|value| value.parse::<u32>().ok()),
        commit_sha: env_trimmed("BORINGCACHE_CI_SHA"),
    })
}

fn detect_github_actions_run_context() -> Option<CiRunContext> {
    if env_trimmed("GITHUB_ACTIONS").as_deref() != Some("true") {
        return None;
    }

    let run_uid = env_trimmed("GITHUB_RUN_ID")?;
    let source_ref = env_trimmed("GITHUB_REF");
    let ref_name = env_trimmed("GITHUB_REF_NAME");
    let head_ref = env_trimmed("GITHUB_HEAD_REF");
    let base_ref = env_trimmed("GITHUB_BASE_REF");
    let pull_request_number =
        github_pull_request_number(source_ref.as_deref(), ref_name.as_deref());
    let source_ref_type = if pull_request_number.is_some() {
        CiSourceRefType::PullRequest
    } else {
        github_source_ref_type(source_ref.as_deref())
    };
    let source_ref_name = match source_ref_type {
        CiSourceRefType::PullRequest => head_ref.clone().or(ref_name),
        CiSourceRefType::Branch => {
            ref_name.or_else(|| strip_ref_prefix(source_ref.as_deref(), "refs/heads/"))
        }
        CiSourceRefType::Tag => {
            ref_name.or_else(|| strip_ref_prefix(source_ref.as_deref(), "refs/tags/"))
        }
        CiSourceRefType::Other => ref_name,
    };

    Some(CiRunContext {
        provider: "github-actions".to_string(),
        run_uid,
        run_attempt: env_trimmed("GITHUB_RUN_ATTEMPT"),
        repository: env_trimmed("GITHUB_REPOSITORY"),
        source_ref_type,
        source_ref,
        source_ref_name,
        head_ref_name: head_ref,
        base_ref_name: base_ref.clone(),
        default_branch: env_trimmed("GITHUB_DEFAULT_BRANCH").or(base_ref),
        pull_request_number,
        commit_sha: env_trimmed("GITHUB_SHA"),
    })
}

fn github_source_ref_type(source_ref: Option<&str>) -> CiSourceRefType {
    match source_ref {
        Some(value) if value.starts_with("refs/heads/") => CiSourceRefType::Branch,
        Some(value) if value.starts_with("refs/tags/") => CiSourceRefType::Tag,
        Some(value) if value.starts_with("refs/pull/") => CiSourceRefType::PullRequest,
        _ => env_trimmed("GITHUB_REF_TYPE")
            .as_deref()
            .map(parse_source_ref_type)
            .unwrap_or(CiSourceRefType::Other),
    }
}

fn github_pull_request_number(source_ref: Option<&str>, ref_name: Option<&str>) -> Option<u32> {
    source_ref
        .and_then(|value| parse_github_pull_ref_number(value.strip_prefix("refs/pull/")?))
        .or_else(|| ref_name.and_then(parse_github_pull_ref_number))
        .or_else(github_event_pull_request_number)
}

fn parse_github_pull_ref_number(value: &str) -> Option<u32> {
    value.split('/').next()?.parse::<u32>().ok()
}

fn github_event_pull_request_number() -> Option<u32> {
    let path = env_trimmed("GITHUB_EVENT_PATH")?;
    let bytes = std::fs::read(path).ok()?;
    let json = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?;
    json.get("number")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| {
            json.get("pull_request")
                .and_then(|pull_request| pull_request.get("number"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        })
}

fn strip_ref_prefix(source_ref: Option<&str>, prefix: &str) -> Option<String> {
    source_ref
        .and_then(|value| value.strip_prefix(prefix))
        .map(ToOwned::to_owned)
}

fn parse_source_ref_type(value: &str) -> CiSourceRefType {
    match value.trim().to_ascii_lowercase().as_str() {
        "branch" => CiSourceRefType::Branch,
        "tag" => CiSourceRefType::Tag,
        "pull-request" | "pull_request" | "pr" => CiSourceRefType::PullRequest,
        _ => CiSourceRefType::Other,
    }
}

fn env_trimmed(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

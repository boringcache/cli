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
    ("TF_BUILD", "azure-devops"),
    ("TEAMCITY_VERSION", "teamcity"),
    ("BAMBOO_BUILD_KEY", "bamboo"),
    ("CODEBUILD_BUILD_ID", "aws-codebuild"),
    ("BITBUCKET_BUILD_NUMBER", "bitbucket-pipelines"),
    ("BITBUCKET_PIPELINE_UUID", "bitbucket-pipelines"),
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
        if env::var(env_var).is_ok() && !providers.contains(name) {
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
    detect_provider_neutral_run_context()
        .or_else(detect_github_actions_run_context)
        .or_else(detect_gitlab_ci_run_context)
        .or_else(detect_circleci_run_context)
        .or_else(detect_buildkite_run_context)
        .or_else(detect_bitbucket_pipelines_run_context)
        .or_else(detect_travis_ci_run_context)
        .or_else(detect_azure_devops_run_context)
        .or_else(detect_jenkins_run_context)
        .or_else(detect_aws_codebuild_run_context)
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
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
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
        default_branch: env_trimmed("GITHUB_DEFAULT_BRANCH")
            .or_else(crate::github_event::default_branch_from_env)
            .or(base_ref),
        pull_request_number,
        commit_sha: env_trimmed("GITHUB_SHA"),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_gitlab_ci_run_context() -> Option<CiRunContext> {
    if env_trimmed("GITLAB_CI").as_deref() != Some("true") {
        return None;
    }

    let run_uid = env_trimmed("CI_PIPELINE_ID")?;
    let pull_request_number = parse_ci_number(env_trimmed("CI_MERGE_REQUEST_IID").as_deref());
    let tag = env_trimmed("CI_COMMIT_TAG");
    let branch = env_trimmed("CI_COMMIT_BRANCH").or_else(|| env_trimmed("CI_COMMIT_REF_NAME"));
    let source_ref_type = branch_tag_or_pr_ref_type(
        pull_request_number.is_some(),
        branch.as_deref(),
        tag.as_deref(),
    );
    let source_ref_name = match source_ref_type {
        CiSourceRefType::PullRequest => {
            env_trimmed("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME").or(branch.clone())
        }
        CiSourceRefType::Tag => tag.clone(),
        CiSourceRefType::Branch | CiSourceRefType::Other => branch.clone().or(tag.clone()),
    };

    Some(CiRunContext {
        provider: "gitlab-ci".to_string(),
        run_uid,
        run_attempt: None,
        repository: env_trimmed("CI_PROJECT_PATH"),
        source_ref_type,
        source_ref: env_trimmed("CI_COMMIT_REF_NAME"),
        source_ref_name,
        head_ref_name: env_trimmed("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
        base_ref_name: env_trimmed("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
        default_branch: env_trimmed("CI_DEFAULT_BRANCH"),
        pull_request_number,
        commit_sha: env_trimmed("CI_COMMIT_SHA"),
        run_started_at: env_trimmed("CI_PIPELINE_CREATED_AT")
            .or_else(|| env_trimmed("CI_JOB_STARTED_AT"))
            .or_else(|| env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT")),
    })
}

fn detect_circleci_run_context() -> Option<CiRunContext> {
    if env_trimmed("CIRCLECI").as_deref() != Some("true") {
        return None;
    }

    let run_uid = env_trimmed("CIRCLE_WORKFLOW_ID")
        .or_else(|| env_trimmed("CIRCLE_PIPELINE_ID"))
        .or_else(|| env_trimmed("CIRCLE_BUILD_NUM"))?;
    let pull_request_number = parse_ci_number(env_trimmed("CIRCLE_PR_NUMBER").as_deref())
        .or_else(|| pull_request_number_from_url(env_trimmed("CIRCLE_PULL_REQUEST").as_deref()));
    let tag = env_trimmed("CIRCLE_TAG");
    let branch = env_trimmed("CIRCLE_BRANCH");
    let source_ref_type = branch_tag_or_pr_ref_type(
        pull_request_number.is_some(),
        branch.as_deref(),
        tag.as_deref(),
    );

    Some(CiRunContext {
        provider: "circleci".to_string(),
        run_uid,
        run_attempt: None,
        repository: repository_from_parts(
            env_trimmed("CIRCLE_PROJECT_USERNAME"),
            env_trimmed("CIRCLE_PROJECT_REPONAME"),
        ),
        source_ref_type,
        source_ref: tag.clone().or(branch.clone()),
        source_ref_name: tag.or(branch),
        head_ref_name: env_trimmed("CIRCLE_BRANCH"),
        base_ref_name: None,
        default_branch: None,
        pull_request_number,
        commit_sha: env_trimmed("CIRCLE_SHA1"),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_buildkite_run_context() -> Option<CiRunContext> {
    if env_trimmed("BUILDKITE").as_deref() != Some("true") {
        return None;
    }

    let run_uid =
        env_trimmed("BUILDKITE_BUILD_ID").or_else(|| env_trimmed("BUILDKITE_BUILD_NUMBER"))?;
    let pull_request_number = parse_ci_number(env_trimmed("BUILDKITE_PULL_REQUEST").as_deref());
    let tag = env_trimmed("BUILDKITE_TAG");
    let branch = env_trimmed("BUILDKITE_BRANCH");
    let source_ref_type = branch_tag_or_pr_ref_type(
        pull_request_number.is_some(),
        branch.as_deref(),
        tag.as_deref(),
    );

    Some(CiRunContext {
        provider: "buildkite".to_string(),
        run_uid,
        run_attempt: None,
        repository: repository_from_parts(
            env_trimmed("BUILDKITE_ORGANIZATION_SLUG"),
            env_trimmed("BUILDKITE_PIPELINE_SLUG"),
        )
        .or_else(|| env_trimmed("BUILDKITE_PIPELINE_SLUG")),
        source_ref_type,
        source_ref: tag.clone().or(branch.clone()),
        source_ref_name: tag.or(branch.clone()),
        head_ref_name: branch,
        base_ref_name: env_trimmed("BUILDKITE_PULL_REQUEST_BASE_BRANCH"),
        default_branch: None,
        pull_request_number,
        commit_sha: env_trimmed("BUILDKITE_COMMIT"),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_bitbucket_pipelines_run_context() -> Option<CiRunContext> {
    let run_uid =
        env_trimmed("BITBUCKET_PIPELINE_UUID").or_else(|| env_trimmed("BITBUCKET_BUILD_NUMBER"))?;

    let pull_request_number = parse_ci_number(env_trimmed("BITBUCKET_PR_ID").as_deref());
    let tag = env_trimmed("BITBUCKET_TAG");
    let branch = env_trimmed("BITBUCKET_BRANCH");
    let source_ref_type = branch_tag_or_pr_ref_type(
        pull_request_number.is_some(),
        branch.as_deref(),
        tag.as_deref(),
    );

    Some(CiRunContext {
        provider: "bitbucket-pipelines".to_string(),
        run_uid,
        run_attempt: None,
        repository: env_trimmed("BITBUCKET_REPO_FULL_NAME").or_else(|| {
            repository_from_parts(
                env_trimmed("BITBUCKET_WORKSPACE"),
                env_trimmed("BITBUCKET_REPO_SLUG"),
            )
        }),
        source_ref_type,
        source_ref: tag.clone().or(branch.clone()),
        source_ref_name: tag.or(branch.clone()),
        head_ref_name: branch,
        base_ref_name: env_trimmed("BITBUCKET_PR_DESTINATION_BRANCH"),
        default_branch: None,
        pull_request_number,
        commit_sha: env_trimmed("BITBUCKET_COMMIT"),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_travis_ci_run_context() -> Option<CiRunContext> {
    if env_trimmed("TRAVIS").as_deref() != Some("true") {
        return None;
    }

    let run_uid = env_trimmed("TRAVIS_BUILD_ID")?;
    let pull_request_number = parse_ci_number(env_trimmed("TRAVIS_PULL_REQUEST").as_deref());
    let tag = env_trimmed("TRAVIS_TAG");
    let branch = env_trimmed("TRAVIS_BRANCH");
    let source_ref_type = branch_tag_or_pr_ref_type(
        pull_request_number.is_some(),
        branch.as_deref(),
        tag.as_deref(),
    );
    let pr_branch = env_trimmed("TRAVIS_PULL_REQUEST_BRANCH");
    let source_ref_name = match source_ref_type {
        CiSourceRefType::PullRequest => pr_branch.clone().or(branch.clone()),
        CiSourceRefType::Tag => tag.clone(),
        CiSourceRefType::Branch | CiSourceRefType::Other => branch.clone().or(tag.clone()),
    };

    Some(CiRunContext {
        provider: "travis-ci".to_string(),
        run_uid,
        run_attempt: None,
        repository: env_trimmed("TRAVIS_REPO_SLUG"),
        source_ref_type,
        source_ref: tag.clone().or(branch.clone()),
        source_ref_name,
        head_ref_name: pr_branch,
        base_ref_name: branch,
        default_branch: None,
        pull_request_number,
        commit_sha: env_trimmed("TRAVIS_PULL_REQUEST_SHA").or_else(|| env_trimmed("TRAVIS_COMMIT")),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_azure_devops_run_context() -> Option<CiRunContext> {
    if env_trimmed("TF_BUILD").is_none() && env_trimmed("AZURE_HTTP_USER_AGENT").is_none() {
        return None;
    }

    let run_uid = env_trimmed("BUILD_BUILDID")?;
    let source_ref = env_trimmed("BUILD_SOURCEBRANCH");
    let pull_request_number =
        parse_ci_number(env_trimmed("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER").as_deref())
            .or_else(|| parse_ci_number(env_trimmed("SYSTEM_PULLREQUEST_PULLREQUESTID").as_deref()))
            .or_else(|| azure_pull_request_number(source_ref.as_deref()));
    let source_ref_type = if pull_request_number.is_some() {
        CiSourceRefType::PullRequest
    } else {
        prefixed_ref_type(source_ref.as_deref())
    };
    let source_ref_name = match source_ref_type {
        CiSourceRefType::PullRequest => {
            strip_any_ref_prefix(env_trimmed("SYSTEM_PULLREQUEST_SOURCEBRANCH").as_deref())
                .or_else(|| env_trimmed("BUILD_SOURCEBRANCHNAME"))
        }
        CiSourceRefType::Branch | CiSourceRefType::Tag => {
            strip_any_ref_prefix(source_ref.as_deref())
                .or_else(|| env_trimmed("BUILD_SOURCEBRANCHNAME"))
        }
        CiSourceRefType::Other => env_trimmed("BUILD_SOURCEBRANCHNAME"),
    };

    Some(CiRunContext {
        provider: "azure-devops".to_string(),
        run_uid,
        run_attempt: None,
        repository: env_trimmed("BUILD_REPOSITORY_NAME"),
        source_ref_type,
        source_ref,
        source_ref_name,
        head_ref_name: strip_any_ref_prefix(
            env_trimmed("SYSTEM_PULLREQUEST_SOURCEBRANCH").as_deref(),
        ),
        base_ref_name: strip_any_ref_prefix(
            env_trimmed("SYSTEM_PULLREQUEST_TARGETBRANCH").as_deref(),
        ),
        default_branch: strip_any_ref_prefix(
            env_trimmed("BUILD_REPOSITORY_DEFAULTBRANCH").as_deref(),
        ),
        pull_request_number,
        commit_sha: env_trimmed("SYSTEM_PULLREQUEST_SOURCECOMMITID")
            .or_else(|| env_trimmed("BUILD_SOURCEVERSION")),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_jenkins_run_context() -> Option<CiRunContext> {
    env_trimmed("JENKINS_URL")?;

    let run_uid = env_trimmed("BUILD_TAG")
        .or_else(|| env_trimmed("BUILD_ID"))
        .or_else(|| env_trimmed("BUILD_NUMBER"))?;
    let pull_request_number = parse_ci_number(env_trimmed("CHANGE_ID").as_deref());
    let tag = env_trimmed("TAG_NAME");
    let branch = env_trimmed("BRANCH_NAME").or_else(|| env_trimmed("GIT_BRANCH"));
    let source_ref_type = branch_tag_or_pr_ref_type(
        pull_request_number.is_some(),
        branch.as_deref(),
        tag.as_deref(),
    );
    let source_ref_name = match source_ref_type {
        CiSourceRefType::PullRequest => env_trimmed("CHANGE_BRANCH").or(branch.clone()),
        CiSourceRefType::Tag => tag.clone(),
        CiSourceRefType::Branch | CiSourceRefType::Other => branch.clone().or(tag.clone()),
    };

    Some(CiRunContext {
        provider: "jenkins".to_string(),
        run_uid,
        run_attempt: None,
        repository: env_trimmed("JOB_NAME"),
        source_ref_type,
        source_ref: tag.clone().or(branch.clone()),
        source_ref_name,
        head_ref_name: env_trimmed("CHANGE_BRANCH"),
        base_ref_name: env_trimmed("CHANGE_TARGET"),
        default_branch: None,
        pull_request_number,
        commit_sha: env_trimmed("GIT_COMMIT"),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
    })
}

fn detect_aws_codebuild_run_context() -> Option<CiRunContext> {
    let run_uid = env_trimmed("CODEBUILD_BUILD_ID")?;
    let source_ref = env_trimmed("CODEBUILD_WEBHOOK_HEAD_REF")
        .or_else(|| env_trimmed("CODEBUILD_SOURCE_VERSION"));
    let pull_request_number = codebuild_pull_request_number(
        env_trimmed("CODEBUILD_WEBHOOK_TRIGGER")
            .or_else(|| env_trimmed("CODEBUILD_SOURCE_VERSION"))
            .as_deref(),
    );
    let source_ref_type = if pull_request_number.is_some() {
        CiSourceRefType::PullRequest
    } else {
        prefixed_ref_type(source_ref.as_deref())
    };

    Some(CiRunContext {
        provider: "aws-codebuild".to_string(),
        run_uid,
        run_attempt: None,
        repository: repository_from_parts(
            env_trimmed("CODEBUILD_RUNNER_OWNER"),
            env_trimmed("CODEBUILD_RUNNER_REPO"),
        )
        .or_else(|| codebuild_project_from_build_id(env_trimmed("CODEBUILD_BUILD_ID").as_deref())),
        source_ref_type,
        source_ref: source_ref.clone(),
        source_ref_name: strip_any_ref_prefix(source_ref.as_deref()),
        head_ref_name: strip_any_ref_prefix(env_trimmed("CODEBUILD_WEBHOOK_HEAD_REF").as_deref()),
        base_ref_name: strip_any_ref_prefix(env_trimmed("CODEBUILD_WEBHOOK_BASE_REF").as_deref()),
        default_branch: None,
        pull_request_number,
        commit_sha: env_trimmed("CODEBUILD_RESOLVED_SOURCE_VERSION"),
        run_started_at: env_trimmed("BORINGCACHE_CI_RUN_STARTED_AT"),
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
        .or_else(crate::github_event::pull_request_number_from_env)
}

fn parse_github_pull_ref_number(value: &str) -> Option<u32> {
    value.split('/').next()?.parse::<u32>().ok()
}

fn strip_ref_prefix(source_ref: Option<&str>, prefix: &str) -> Option<String> {
    source_ref
        .and_then(|value| value.strip_prefix(prefix))
        .map(ToOwned::to_owned)
}

fn strip_any_ref_prefix(source_ref: Option<&str>) -> Option<String> {
    source_ref.map(|value| {
        value
            .strip_prefix("refs/heads/")
            .or_else(|| value.strip_prefix("refs/tags/"))
            .or_else(|| value.strip_prefix("refs/pull/"))
            .unwrap_or(value)
            .to_string()
    })
}

fn prefixed_ref_type(source_ref: Option<&str>) -> CiSourceRefType {
    match source_ref {
        Some(value) if value.starts_with("refs/heads/") => CiSourceRefType::Branch,
        Some(value) if value.starts_with("refs/tags/") => CiSourceRefType::Tag,
        Some(value) if value.starts_with("refs/pull/") => CiSourceRefType::PullRequest,
        Some(value) if value.starts_with("branch/") => CiSourceRefType::Branch,
        Some(value) if value.starts_with("tag/") => CiSourceRefType::Tag,
        _ => CiSourceRefType::Other,
    }
}

fn branch_tag_or_pr_ref_type(
    pull_request: bool,
    branch: Option<&str>,
    tag: Option<&str>,
) -> CiSourceRefType {
    if pull_request {
        CiSourceRefType::PullRequest
    } else if tag.is_some() {
        CiSourceRefType::Tag
    } else if branch.is_some() {
        CiSourceRefType::Branch
    } else {
        CiSourceRefType::Other
    }
}

fn repository_from_parts(owner: Option<String>, repo: Option<String>) -> Option<String> {
    Some(format!("{}/{}", owner?, repo?))
}

fn parse_ci_number(value: Option<&str>) -> Option<u32> {
    let value = value?.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("false") {
        return None;
    }

    value.parse::<u32>().ok()
}

fn pull_request_number_from_url(value: Option<&str>) -> Option<u32> {
    let value = value?.trim().trim_end_matches('/');
    value.rsplit('/').next()?.parse::<u32>().ok()
}

fn azure_pull_request_number(source_ref: Option<&str>) -> Option<u32> {
    source_ref
        .and_then(|value| value.strip_prefix("refs/pull/"))
        .and_then(|value| value.split('/').next())
        .and_then(|value| value.parse::<u32>().ok())
}

fn codebuild_pull_request_number(source_ref: Option<&str>) -> Option<u32> {
    source_ref
        .and_then(|value| value.strip_prefix("pr/"))
        .and_then(|value| value.split('/').next())
        .and_then(|value| value.parse::<u32>().ok())
}

fn codebuild_project_from_build_id(value: Option<&str>) -> Option<String> {
    value
        .and_then(|build_id| build_id.split(':').next())
        .map(str::to_string)
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

use std::env;

use super::CiContext;

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

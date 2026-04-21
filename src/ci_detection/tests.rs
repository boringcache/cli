use super::*;
use crate::test_env;
use std::env;

fn clear_ci_env_vars() {
    let ci_vars = [
        "CI",
        "GITHUB_ACTIONS",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "GITHUB_REF_TYPE",
        "GITHUB_HEAD_REF",
        "GITHUB_BASE_REF",
        "GITHUB_DEFAULT_BRANCH",
        "GITHUB_EVENT_PATH",
        "GITHUB_SHA",
        "GITLAB_CI",
        "CIRCLECI",
        "JENKINS_URL",
        "BUILDKITE",
        "TRAVIS",
        "APPVEYOR",
        "AZURE_HTTP_USER_AGENT",
        "TEAMCITY_VERSION",
        "BAMBOO_BUILD_KEY",
        "CODEBUILD_BUILD_ID",
        "BITBUCKET_BUILD_NUMBER",
        "DRONE",
        "SEMAPHORE",
        "WERCKER",
        "NETLIFY",
        "VERCEL",
        "RENDER",
        "HEROKU_APP_ID",
        "BORINGCACHE_CI_PROVIDER",
        "BORINGCACHE_CI_RUN_ID",
        "BORINGCACHE_CI_RUN_ATTEMPT",
        "BORINGCACHE_CI_REPOSITORY",
        "BORINGCACHE_CI_REF",
        "BORINGCACHE_CI_REF_NAME",
        "BORINGCACHE_CI_REF_TYPE",
        "BORINGCACHE_CI_HEAD_REF",
        "BORINGCACHE_CI_BASE_REF",
        "BORINGCACHE_CI_DEFAULT_BRANCH",
        "BORINGCACHE_CI_PR_NUMBER",
        "BORINGCACHE_CI_SHA",
        "BORINGCACHE_CI_RUN_STARTED_AT",
    ];

    for var in &ci_vars {
        test_env::remove_var(var);
    }
}

#[test]
fn detects_provider_neutral_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("BORINGCACHE_CI_PROVIDER", "example-ci");
    test_env::set_var("BORINGCACHE_CI_RUN_ID", "run-42");
    test_env::set_var("BORINGCACHE_CI_RUN_ATTEMPT", "2");
    test_env::set_var("BORINGCACHE_CI_REF_TYPE", "pull-request");
    test_env::set_var("BORINGCACHE_CI_PR_NUMBER", "17");
    test_env::set_var("BORINGCACHE_CI_HEAD_REF", "feature/docker-cache");
    test_env::set_var("BORINGCACHE_CI_DEFAULT_BRANCH", "main");
    test_env::set_var("BORINGCACHE_CI_RUN_STARTED_AT", "2026-04-21T10:00:00Z");

    let context = detect_ci_context();
    let run = context.run_context().expect("provider-neutral run context");

    assert_eq!(run.provider, "example-ci");
    assert_eq!(run.run_uid, "run-42");
    assert_eq!(run.run_attempt.as_deref(), Some("2"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.pull_request_number, Some(17));
    assert_eq!(run.head_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.default_branch.as_deref(), Some("main"));
    assert_eq!(run.run_started_at.as_deref(), Some("2026-04-21T10:00:00Z"));

    clear_ci_env_vars();
}

#[test]
fn detects_github_actions_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("GITHUB_ACTIONS", "true");
    test_env::set_var("GITHUB_RUN_ID", "123456789");
    test_env::set_var("GITHUB_RUN_ATTEMPT", "3");
    test_env::set_var("GITHUB_REPOSITORY", "acme/widgets");
    test_env::set_var("GITHUB_REF", "refs/pull/42/merge");
    test_env::set_var("GITHUB_REF_NAME", "42/merge");
    test_env::set_var("GITHUB_HEAD_REF", "feature/docker-cache");
    test_env::set_var("GITHUB_BASE_REF", "main");
    test_env::set_var("GITHUB_SHA", "abcdef1234567890");

    let context = detect_ci_context();
    let run = context.run_context().expect("GitHub Actions run context");

    assert_eq!(run.provider, "github-actions");
    assert_eq!(run.run_uid, "123456789");
    assert_eq!(run.run_attempt.as_deref(), Some("3"));
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.default_branch.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(42));
    assert_eq!(run.commit_sha.as_deref(), Some("abcdef1234567890"));

    clear_ci_env_vars();
}

#[test]
#[ignore]
fn test_github_actions_detection() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("GITHUB_ACTIONS", "true");
    let result = detect_ci_environment();
    clear_ci_env_vars();
    assert_eq!(result, "github-actions");
}

#[test]
#[ignore]
fn test_local_detection() {
    let _guard = test_env::lock();
    let original_env: Vec<_> = env::vars().collect();

    clear_ci_env_vars();
    let result = detect_ci_environment();

    for (key, _) in env::vars() {
        if key.starts_with("CI") || key.contains("ACTIONS") || key.contains("GITLAB") {
            test_env::remove_var(key);
        }
    }
    for (key, value) in original_env {
        if key.starts_with("CI") || key.contains("ACTIONS") || key.contains("GITLAB") {
            test_env::set_var(key, value);
        }
    }

    assert!(
        result == "local" || result == "github-actions" || result.contains("ci"),
        "Expected 'local' or a CI environment, got: {result}"
    );
}

#[test]
#[ignore]
fn test_multiple_ci_detection() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("GITHUB_ACTIONS", "true");
    test_env::set_var("CI", "true");
    let result = detect_ci_environment();
    clear_ci_env_vars();
    assert!(result.contains("github-actions"));
}

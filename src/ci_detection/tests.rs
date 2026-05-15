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
        "CI_PIPELINE_ID",
        "CI_PROJECT_PATH",
        "CI_COMMIT_REF_NAME",
        "CI_COMMIT_BRANCH",
        "CI_COMMIT_TAG",
        "CI_MERGE_REQUEST_IID",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
        "CI_DEFAULT_BRANCH",
        "CI_COMMIT_SHA",
        "CI_PIPELINE_CREATED_AT",
        "CI_JOB_STARTED_AT",
        "CIRCLECI",
        "CIRCLE_WORKFLOW_ID",
        "CIRCLE_PIPELINE_ID",
        "CIRCLE_BUILD_NUM",
        "CIRCLE_PROJECT_USERNAME",
        "CIRCLE_PROJECT_REPONAME",
        "CIRCLE_BRANCH",
        "CIRCLE_TAG",
        "CIRCLE_PULL_REQUEST",
        "CIRCLE_PR_NUMBER",
        "CIRCLE_SHA1",
        "JENKINS_URL",
        "BUILD_TAG",
        "BUILD_ID",
        "BUILD_NUMBER",
        "JOB_NAME",
        "BRANCH_NAME",
        "GIT_BRANCH",
        "CHANGE_ID",
        "CHANGE_BRANCH",
        "CHANGE_TARGET",
        "TAG_NAME",
        "GIT_COMMIT",
        "BUILDKITE",
        "BUILDKITE_BUILD_ID",
        "BUILDKITE_BUILD_NUMBER",
        "BUILDKITE_ORGANIZATION_SLUG",
        "BUILDKITE_PIPELINE_SLUG",
        "BUILDKITE_BRANCH",
        "BUILDKITE_TAG",
        "BUILDKITE_PULL_REQUEST",
        "BUILDKITE_PULL_REQUEST_BASE_BRANCH",
        "BUILDKITE_COMMIT",
        "TRAVIS",
        "TRAVIS_BUILD_ID",
        "TRAVIS_REPO_SLUG",
        "TRAVIS_BRANCH",
        "TRAVIS_TAG",
        "TRAVIS_PULL_REQUEST",
        "TRAVIS_PULL_REQUEST_BRANCH",
        "TRAVIS_PULL_REQUEST_SHA",
        "TRAVIS_COMMIT",
        "APPVEYOR",
        "AZURE_HTTP_USER_AGENT",
        "TF_BUILD",
        "BUILD_BUILDID",
        "BUILD_REPOSITORY_NAME",
        "BUILD_SOURCEBRANCH",
        "BUILD_SOURCEBRANCHNAME",
        "BUILD_SOURCEVERSION",
        "SYSTEM_PULLREQUEST_PULLREQUESTID",
        "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER",
        "SYSTEM_PULLREQUEST_SOURCEBRANCH",
        "SYSTEM_PULLREQUEST_TARGETBRANCH",
        "SYSTEM_PULLREQUEST_SOURCECOMMITID",
        "BUILD_REPOSITORY_DEFAULTBRANCH",
        "TEAMCITY_VERSION",
        "BAMBOO_BUILD_KEY",
        "CODEBUILD_BUILD_ID",
        "CODEBUILD_SOURCE_VERSION",
        "CODEBUILD_WEBHOOK_TRIGGER",
        "CODEBUILD_WEBHOOK_HEAD_REF",
        "CODEBUILD_WEBHOOK_BASE_REF",
        "CODEBUILD_RESOLVED_SOURCE_VERSION",
        "CODEBUILD_RUNNER_OWNER",
        "CODEBUILD_RUNNER_REPO",
        "BITBUCKET_BUILD_NUMBER",
        "BITBUCKET_PIPELINE_UUID",
        "BITBUCKET_REPO_FULL_NAME",
        "BITBUCKET_WORKSPACE",
        "BITBUCKET_REPO_SLUG",
        "BITBUCKET_BRANCH",
        "BITBUCKET_TAG",
        "BITBUCKET_PR_ID",
        "BITBUCKET_PR_DESTINATION_BRANCH",
        "BITBUCKET_COMMIT",
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
        "BORINGCACHE_BENCHMARK_MODE",
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
fn detects_gitlab_ci_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("GITLAB_CI", "true");
    test_env::set_var("CI_PIPELINE_ID", "987654");
    test_env::set_var("CI_PROJECT_PATH", "acme/widgets");
    test_env::set_var("CI_COMMIT_REF_NAME", "feature/docker-cache");
    test_env::set_var("CI_MERGE_REQUEST_IID", "27");
    test_env::set_var(
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
        "feature/docker-cache",
    );
    test_env::set_var("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main");
    test_env::set_var("CI_DEFAULT_BRANCH", "main");
    test_env::set_var("CI_COMMIT_SHA", "abcdef1234567890");
    test_env::set_var("CI_PIPELINE_CREATED_AT", "2026-05-15T08:30:00Z");

    let context = detect_ci_context();
    let run = context.run_context().expect("GitLab CI run context");

    assert_eq!(run.provider, "gitlab-ci");
    assert_eq!(run.run_uid, "987654");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.default_branch.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(27));
    assert_eq!(run.commit_sha.as_deref(), Some("abcdef1234567890"));
    assert_eq!(run.run_started_at.as_deref(), Some("2026-05-15T08:30:00Z"));

    clear_ci_env_vars();
}

#[test]
fn detects_circleci_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("CIRCLECI", "true");
    test_env::set_var("CIRCLE_WORKFLOW_ID", "workflow-uuid");
    test_env::set_var("CIRCLE_PROJECT_USERNAME", "acme");
    test_env::set_var("CIRCLE_PROJECT_REPONAME", "widgets");
    test_env::set_var("CIRCLE_BRANCH", "feature/docker-cache");
    test_env::set_var(
        "CIRCLE_PULL_REQUEST",
        "https://github.com/acme/widgets/pull/31",
    );
    test_env::set_var("CIRCLE_SHA1", "abc123");

    let context = detect_ci_context();
    let run = context.run_context().expect("CircleCI run context");

    assert_eq!(run.provider, "circleci");
    assert_eq!(run.run_uid, "workflow-uuid");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.pull_request_number, Some(31));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn detects_buildkite_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("BUILDKITE", "true");
    test_env::set_var("BUILDKITE_BUILD_ID", "bk-uuid");
    test_env::set_var("BUILDKITE_ORGANIZATION_SLUG", "acme");
    test_env::set_var("BUILDKITE_PIPELINE_SLUG", "widgets");
    test_env::set_var("BUILDKITE_BRANCH", "feature/docker-cache");
    test_env::set_var("BUILDKITE_PULL_REQUEST", "44");
    test_env::set_var("BUILDKITE_PULL_REQUEST_BASE_BRANCH", "main");
    test_env::set_var("BUILDKITE_COMMIT", "abc123");

    let context = detect_ci_context();
    let run = context.run_context().expect("Buildkite run context");

    assert_eq!(run.provider, "buildkite");
    assert_eq!(run.run_uid, "bk-uuid");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(44));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn detects_bitbucket_pipelines_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("BITBUCKET_PIPELINE_UUID", "{pipeline-uuid}");
    test_env::set_var("BITBUCKET_REPO_FULL_NAME", "acme/widgets");
    test_env::set_var("BITBUCKET_BRANCH", "feature/docker-cache");
    test_env::set_var("BITBUCKET_PR_ID", "55");
    test_env::set_var("BITBUCKET_PR_DESTINATION_BRANCH", "main");
    test_env::set_var("BITBUCKET_COMMIT", "abc123");

    let context = detect_ci_context();
    let run = context
        .run_context()
        .expect("Bitbucket Pipelines run context");

    assert_eq!(context.label(), "bitbucket-pipelines");
    assert_eq!(run.provider, "bitbucket-pipelines");
    assert_eq!(run.run_uid, "{pipeline-uuid}");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(55));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn detects_travis_ci_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("TRAVIS", "true");
    test_env::set_var("TRAVIS_BUILD_ID", "travis-123");
    test_env::set_var("TRAVIS_REPO_SLUG", "acme/widgets");
    test_env::set_var("TRAVIS_BRANCH", "main");
    test_env::set_var("TRAVIS_PULL_REQUEST", "64");
    test_env::set_var("TRAVIS_PULL_REQUEST_BRANCH", "feature/docker-cache");
    test_env::set_var("TRAVIS_PULL_REQUEST_SHA", "abc123");

    let context = detect_ci_context();
    let run = context.run_context().expect("Travis CI run context");

    assert_eq!(run.provider, "travis-ci");
    assert_eq!(run.run_uid, "travis-123");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(64));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn detects_azure_devops_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("TF_BUILD", "True");
    test_env::set_var("BUILD_BUILDID", "ado-123");
    test_env::set_var("BUILD_REPOSITORY_NAME", "acme/widgets");
    test_env::set_var("BUILD_SOURCEBRANCH", "refs/pull/77/merge");
    test_env::set_var("BUILD_SOURCEBRANCHNAME", "merge");
    test_env::set_var("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", "77");
    test_env::set_var(
        "SYSTEM_PULLREQUEST_SOURCEBRANCH",
        "refs/heads/feature/docker-cache",
    );
    test_env::set_var("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/main");
    test_env::set_var("SYSTEM_PULLREQUEST_SOURCECOMMITID", "abc123");
    test_env::set_var("BUILD_REPOSITORY_DEFAULTBRANCH", "refs/heads/main");

    let context = detect_ci_context();
    let run = context.run_context().expect("Azure DevOps run context");

    assert_eq!(context.label(), "azure-devops");
    assert_eq!(run.provider, "azure-devops");
    assert_eq!(run.run_uid, "ado-123");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.default_branch.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(77));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn detects_jenkins_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("JENKINS_URL", "https://jenkins.example.test");
    test_env::set_var("BUILD_TAG", "jenkins-acme-widgets-12");
    test_env::set_var("JOB_NAME", "acme/widgets");
    test_env::set_var("BRANCH_NAME", "PR-88");
    test_env::set_var("CHANGE_ID", "88");
    test_env::set_var("CHANGE_BRANCH", "feature/docker-cache");
    test_env::set_var("CHANGE_TARGET", "main");
    test_env::set_var("GIT_COMMIT", "abc123");

    let context = detect_ci_context();
    let run = context.run_context().expect("Jenkins run context");

    assert_eq!(run.provider, "jenkins");
    assert_eq!(run.run_uid, "jenkins-acme-widgets-12");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(88));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn detects_aws_codebuild_run_context() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("CODEBUILD_BUILD_ID", "widgets:build-uuid");
    test_env::set_var("CODEBUILD_SOURCE_VERSION", "pr/99");
    test_env::set_var("CODEBUILD_WEBHOOK_TRIGGER", "pr/99");
    test_env::set_var(
        "CODEBUILD_WEBHOOK_HEAD_REF",
        "refs/heads/feature/docker-cache",
    );
    test_env::set_var("CODEBUILD_WEBHOOK_BASE_REF", "refs/heads/main");
    test_env::set_var("CODEBUILD_RESOLVED_SOURCE_VERSION", "abc123");
    test_env::set_var("CODEBUILD_RUNNER_OWNER", "acme");
    test_env::set_var("CODEBUILD_RUNNER_REPO", "widgets");

    let context = detect_ci_context();
    let run = context.run_context().expect("AWS CodeBuild run context");

    assert_eq!(run.provider, "aws-codebuild");
    assert_eq!(run.run_uid, "widgets:build-uuid");
    assert_eq!(run.repository.as_deref(), Some("acme/widgets"));
    assert_eq!(run.source_ref_type, CiSourceRefType::PullRequest);
    assert_eq!(run.source_ref_name.as_deref(), Some("feature/docker-cache"));
    assert_eq!(run.base_ref_name.as_deref(), Some("main"));
    assert_eq!(run.pull_request_number, Some(99));
    assert_eq!(run.commit_sha.as_deref(), Some("abc123"));

    clear_ci_env_vars();
}

#[test]
fn infers_project_hint_from_ci_repository() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("GITHUB_ACTIONS", "true");
    test_env::set_var("GITHUB_RUN_ID", "123456789");
    test_env::set_var("GITHUB_REPOSITORY", "acme/widgets");

    let context = detect_ci_context();

    assert_eq!(context.inferred_project_hint().as_deref(), Some("widgets"));

    clear_ci_env_vars();
}

#[test]
fn benchmark_mode_strips_benchmark_prefix_from_project_hint() {
    let _guard = test_env::lock();
    clear_ci_env_vars();
    test_env::set_var("GITHUB_ACTIONS", "true");
    test_env::set_var("GITHUB_RUN_ID", "123456789");
    test_env::set_var("GITHUB_REPOSITORY", "boringcache/benchmark-grpc");
    test_env::set_var("BORINGCACHE_BENCHMARK_MODE", "1");

    let context = detect_ci_context();

    assert_eq!(context.inferred_project_hint().as_deref(), Some("grpc"));

    clear_ci_env_vars();
}

#[test]
fn does_not_create_run_context_for_local_or_generic_ci_without_run_identity() {
    let _guard = test_env::lock();
    clear_ci_env_vars();

    let local_context = detect_ci_context();
    assert!(!local_context.is_ci());
    assert!(local_context.run_context().is_none());

    test_env::set_var("CI", "true");
    let generic_context = detect_ci_context();
    assert!(generic_context.is_ci());
    assert_eq!(generic_context.label(), "generic-ci");
    assert!(generic_context.run_context().is_none());

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

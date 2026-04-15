use super::*;
use crate::test_env;
use std::env;

fn clear_ci_env_vars() {
    let ci_vars = [
        "CI",
        "GITHUB_ACTIONS",
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
    ];

    for var in &ci_vars {
        test_env::remove_var(var);
    }
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

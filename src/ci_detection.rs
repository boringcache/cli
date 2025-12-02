use std::env;

pub fn detect_ci_environment() -> String {
    let ci_indicators = vec![
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

    let mut detected_platforms = Vec::new();

    for (env_var, platform_name) in ci_indicators {
        if env::var(env_var).is_ok() {
            detected_platforms.push(platform_name.to_string());
        }
    }

    if env::var("CI").is_ok() && detected_platforms.is_empty() {
        detected_platforms.push("generic-ci".to_string());
    }

    if detected_platforms.is_empty() {
        "local".to_string()
    } else {
        detected_platforms.join(",")
    }
}

pub fn get_additional_tags() -> Vec<String> {
    let mut tags = Vec::new();

    if let Ok(runner_os) = env::var("RUNNER_OS") {
        tags.push(format!("os:{}", runner_os.to_lowercase()));
    } else if let Ok(os) = env::var("OS") {
        tags.push(format!("os:{}", os.to_lowercase()));
    }

    if let Ok(arch) = env::var("RUNNER_ARCH") {
        tags.push(format!("arch:{}", arch.to_lowercase()));
    }

    if env::var("BORINGCACHE_BENCHMARK_MODE").is_ok() {
        tags.push("benchmark".to_string());
    }

    tags
}

pub fn build_tags_string() -> String {
    let mut all_tags = vec![detect_ci_environment()];
    all_tags.extend(get_additional_tags());
    all_tags.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
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
            env::remove_var(var);
        }
    }

    #[test]
    #[ignore]
    fn test_github_actions_detection() {
        clear_ci_env_vars();
        env::set_var("GITHUB_ACTIONS", "true");
        let result = detect_ci_environment();
        clear_ci_env_vars();
        assert_eq!(result, "github-actions");
    }

    #[test]
    #[ignore]
    fn test_local_detection() {
        let original_env: Vec<_> = env::vars().collect();

        clear_ci_env_vars();
        let result = detect_ci_environment();

        for (key, _) in env::vars() {
            if key.starts_with("CI") || key.contains("ACTIONS") || key.contains("GITLAB") {
                env::remove_var(key);
            }
        }
        for (key, value) in original_env {
            if key.starts_with("CI") || key.contains("ACTIONS") || key.contains("GITLAB") {
                env::set_var(key, value);
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
        clear_ci_env_vars();
        env::set_var("GITHUB_ACTIONS", "true");
        env::set_var("CI", "true");
        let result = detect_ci_environment();
        clear_ci_env_vars();
        assert!(result.contains("github-actions"));
    }
}

use std::env;

#[derive(Debug, Clone, Default)]
pub struct CiContext {
    providers: Vec<&'static str>,
    os_tag: Option<String>,
    arch_tag: Option<String>,
    benchmark: bool,
}

impl CiContext {
    pub fn detect() -> Self {
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

        let mut providers = Vec::new();
        for (env_var, name) in CI_INDICATORS {
            if env::var(env_var).is_ok() {
                providers.push(*name);
            }
        }

        if env::var("CI").is_ok() && providers.is_empty() {
            providers.push("generic-ci");
        }

        let os_tag = env::var("RUNNER_OS")
            .or_else(|_| env::var("OS"))
            .ok()
            .map(|value| format!("os:{}", value.to_lowercase()));

        let arch_tag = env::var("RUNNER_ARCH")
            .ok()
            .map(|value| format!("arch:{}", value.to_lowercase()));

        let benchmark = env::var("BORINGCACHE_BENCHMARK_MODE").is_ok();

        Self {
            providers,
            os_tag,
            arch_tag,
            benchmark,
        }
    }

    pub fn is_ci(&self) -> bool {
        !self.providers.is_empty()
    }

    pub fn label(&self) -> String {
        if self.is_ci() {
            self.providers.join(",")
        } else {
            "local".to_string()
        }
    }

    pub fn tags(&self) -> Vec<String> {
        let mut tags = Vec::new();
        tags.push(self.label());
        if let Some(os) = &self.os_tag {
            tags.push(os.clone());
        }
        if let Some(arch) = &self.arch_tag {
            tags.push(arch.clone());
        }
        if self.benchmark {
            tags.push("benchmark".to_string());
        }
        tags
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

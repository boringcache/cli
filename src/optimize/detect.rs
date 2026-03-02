use super::{CiType, FileRelevance, MAX_CONTENT_LENGTH};

pub fn detect_ci_type(display_path: &str, content: &str) -> CiType {
    if display_path.starts_with(".github/workflows/") {
        return CiType::GitHubActions;
    }

    let name = display_path.rsplit('/').next().unwrap_or(display_path);
    if name.starts_with("Dockerfile") || name.ends_with(".dockerfile") {
        return CiType::Dockerfile;
    }

    match name {
        ".gitlab-ci.yml" => return CiType::GitLabCi,
        ".travis.yml" => return CiType::TravisCi,
        "azure-pipelines.yml" => return CiType::AzurePipelines,
        "bitbucket-pipelines.yml" => return CiType::BitbucketPipelines,
        ".drone.yml" => return CiType::Drone,
        "Jenkinsfile" => return CiType::Jenkins,
        _ => {}
    }

    if display_path.contains(".circleci/") {
        return CiType::CircleCi;
    }
    if display_path.contains(".buildkite/") {
        return CiType::Buildkite;
    }

    detect_ci_type_from_content(content)
}

fn detect_ci_type_from_content(content: &str) -> CiType {
    let scores = [
        (
            CiType::GitHubActions,
            count_patterns(
                content,
                &["jobs:", "runs-on:", "uses:", "steps:", "workflow_dispatch"],
            ),
        ),
        (
            CiType::Dockerfile,
            count_patterns(
                content,
                &["FROM ", "RUN ", "COPY ", "WORKDIR ", "ENTRYPOINT ", "CMD "],
            ),
        ),
        (
            CiType::GitLabCi,
            count_patterns(
                content,
                &[
                    "stages:",
                    "image:",
                    "script:",
                    "artifacts:",
                    "before_script:",
                ],
            ),
        ),
        (
            CiType::CircleCi,
            count_patterns(
                content,
                &["version: 2", "orbs:", "workflows:", "executors:"],
            ),
        ),
        (
            CiType::Buildkite,
            count_patterns(content, &["plugins:", "agents:", "commands:", "label: \""]),
        ),
        (
            CiType::TravisCi,
            count_patterns(
                content,
                &[
                    "language:",
                    "dist:",
                    "before_install:",
                    "after_success:",
                    "addons:",
                ],
            ),
        ),
        (
            CiType::Jenkins,
            count_patterns(content, &["pipeline {", "agent ", "stages {", "stage("]),
        ),
    ];

    scores
        .iter()
        .filter(|(_, score)| *score >= 2)
        .max_by_key(|(_, score)| *score)
        .map(|(ci_type, _)| *ci_type)
        .unwrap_or(CiType::Unknown)
}

fn count_patterns(content: &str, patterns: &[&str]) -> usize {
    patterns.iter().filter(|p| content.contains(**p)).count()
}

pub fn score_relevance(content: &str, ci_type: CiType) -> FileRelevance {
    if content.len() > MAX_CONTENT_LENGTH {
        return FileRelevance::TooLarge;
    }

    let already_optimized_patterns = [
        "boringcache/action",
        "boringcache/save",
        "boringcache/restore",
        "boringcache/docker-action",
        "boringcache/rust-action",
        "boringcache/ruby-action",
        "boringcache/nodejs-action",
        "boringcache/setup-boringcache",
        "boringcache/buildkit-action",
        "boringcache save",
        "boringcache restore",
    ];

    if already_optimized_patterns
        .iter()
        .any(|p| content.contains(p))
    {
        return FileRelevance::AlreadyOptimized;
    }

    let caching_patterns = match ci_type {
        CiType::GitHubActions => vec![
            "actions/cache",
            "actions/cache/save",
            "actions/cache/restore",
            "bundler-cache: true",
            "bundler-cache: 'true'",
            "cache: npm",
            "cache: yarn",
            "cache: pnpm",
            "cache: pip",
            "cache: pipenv",
            "cache: poetry",
            "cache: gradle",
            "cache: maven",
            "cache: 'npm'",
            "cache: 'yarn'",
            "cache: 'pnpm'",
            "cache-from: type=gha",
            "Swatinem/rust-cache",
        ],
        CiType::CircleCi => vec!["save_cache", "restore_cache"],
        CiType::GitLabCi => vec!["cache:", "cache:\n"],
        CiType::Buildkite => vec!["cache#"],
        CiType::Dockerfile => vec![],
        _ => vec!["cache:"],
    };

    if caching_patterns.iter().any(|p| content.contains(p)) {
        let third_party_only_patterns =
            ["namespacelabs/nscloud-cache-action", "namespace-profile-"];
        if third_party_only_patterns
            .iter()
            .any(|p| content.contains(p))
            && !content.contains("actions/cache")
        {
            return FileRelevance::NoOpportunity;
        }
        return FileRelevance::HasCaching;
    }

    let install_patterns = match ci_type {
        CiType::Dockerfile => vec![
            "npm ci",
            "npm install",
            "yarn install",
            "pnpm install",
            "bundle install",
            "gem install",
            "pip install",
            "pip3 install",
            "poetry install",
            "uv sync",
            "cargo build",
            "cargo install",
            "go build",
            "go mod download",
            "gradlew",
            "mvn ",
            "gradle ",
            "apt-get install",
            "apk add",
            "composer install",
        ],
        _ => vec![
            "npm ci",
            "npm install",
            "yarn install",
            "pnpm install",
            "bundle install",
            "gem install",
            "pip install",
            "pip3 install",
            "poetry install",
            "uv sync",
            "cargo build",
            "cargo test",
            "go build",
            "go test",
            "go mod download",
            "./gradlew",
            "mvn ",
            "gradle ",
            "composer install",
            "dotnet restore",
        ],
    };

    if install_patterns.iter().any(|p| content.contains(p)) {
        return FileRelevance::NoCaching;
    }

    FileRelevance::NoOpportunity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_ci_type_from_path() {
        assert_eq!(
            detect_ci_type(".github/workflows/ci.yml", ""),
            CiType::GitHubActions
        );
        assert_eq!(detect_ci_type("Dockerfile", ""), CiType::Dockerfile);
        assert_eq!(
            detect_ci_type("Dockerfile.production", ""),
            CiType::Dockerfile
        );
        assert_eq!(detect_ci_type("app.dockerfile", ""), CiType::Dockerfile);
        assert_eq!(detect_ci_type(".gitlab-ci.yml", ""), CiType::GitLabCi);
        assert_eq!(detect_ci_type(".circleci/config.yml", ""), CiType::CircleCi);
        assert_eq!(
            detect_ci_type(".buildkite/pipeline.yml", ""),
            CiType::Buildkite
        );
        assert_eq!(detect_ci_type(".travis.yml", ""), CiType::TravisCi);
        assert_eq!(detect_ci_type("Jenkinsfile", ""), CiType::Jenkins);
    }

    #[test]
    fn detect_ci_type_from_content_when_path_unknown() {
        let gha = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4";
        assert_eq!(detect_ci_type("unknown.yml", gha), CiType::GitHubActions);

        let dockerfile =
            "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD [\"node\", \"app.js\"]";
        assert_eq!(detect_ci_type("unknown", dockerfile), CiType::Dockerfile);
    }

    #[test]
    fn score_already_optimized() {
        let content = "uses: boringcache/action@v1\n  with:\n    workspace: my-org/app";
        assert_eq!(
            score_relevance(content, CiType::GitHubActions),
            FileRelevance::AlreadyOptimized
        );

        let dockerfile = "RUN boringcache restore my-org/app \"deps:node_modules\"";
        assert_eq!(
            score_relevance(dockerfile, CiType::Dockerfile),
            FileRelevance::AlreadyOptimized
        );
    }

    #[test]
    fn score_has_caching() {
        let content = "- uses: actions/cache@v4\n  with:\n    path: node_modules";
        assert_eq!(
            score_relevance(content, CiType::GitHubActions),
            FileRelevance::HasCaching
        );

        let ruby = "- uses: ruby/setup-ruby@v1\n  with:\n    bundler-cache: true";
        assert_eq!(
            score_relevance(ruby, CiType::GitHubActions),
            FileRelevance::HasCaching
        );

        let circleci = "steps:\n  - restore_cache:\n      keys:\n        - deps-v1";
        assert_eq!(
            score_relevance(circleci, CiType::CircleCi),
            FileRelevance::HasCaching
        );
    }

    #[test]
    fn score_no_caching() {
        let content = "- uses: actions/checkout@v4\n- run: npm ci\n- run: npm test";
        assert_eq!(
            score_relevance(content, CiType::GitHubActions),
            FileRelevance::NoCaching
        );

        let dockerfile = "FROM node:20\nRUN npm ci\nCOPY . .";
        assert_eq!(
            score_relevance(dockerfile, CiType::Dockerfile),
            FileRelevance::NoCaching
        );
    }

    #[test]
    fn score_no_opportunity() {
        let content = "name: Label PR\non: pull_request\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v4";
        assert_eq!(
            score_relevance(content, CiType::GitHubActions),
            FileRelevance::NoOpportunity
        );
    }

    #[test]
    fn score_too_large() {
        let content = "x".repeat(MAX_CONTENT_LENGTH + 1);
        assert_eq!(
            score_relevance(&content, CiType::GitHubActions),
            FileRelevance::TooLarge
        );
    }

    #[test]
    fn score_namespace_labs_only() {
        let content = "- uses: namespacelabs/nscloud-cache-action@v1\n  with:\n    cache: rust\nruns-on: namespace-profile-16x32";
        assert_eq!(
            score_relevance(content, CiType::GitHubActions),
            FileRelevance::NoOpportunity
        );
    }

    #[test]
    fn score_namespace_labs_with_actions_cache() {
        let content = "- uses: namespacelabs/nscloud-cache-action@v1\n- uses: actions/cache@v4\n  with:\n    path: node_modules";
        assert_eq!(
            score_relevance(content, CiType::GitHubActions),
            FileRelevance::HasCaching
        );
    }
}

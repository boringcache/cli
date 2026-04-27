pub mod detect;
pub mod rules_buildkite;
pub mod rules_circleci;
pub mod rules_github_actions;
pub mod rules_gitlab_ci;
pub mod transform;

pub const MAX_CONTENT_LENGTH: usize = 50_000;
pub const MAX_FILES_PER_REQUEST: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiType {
    GitHubActions,
    Dockerfile,
    GitLabCi,
    CircleCi,
    Buildkite,
    TravisCi,
    AzurePipelines,
    BitbucketPipelines,
    Drone,
    Jenkins,
    Unknown,
}

impl CiType {
    pub fn label(self) -> &'static str {
        match self {
            Self::GitHubActions => "GitHub Actions",
            Self::Dockerfile => "Dockerfile",
            Self::GitLabCi => "GitLab CI",
            Self::CircleCi => "CircleCI",
            Self::Buildkite => "Buildkite",
            Self::TravisCi => "Travis CI",
            Self::AzurePipelines => "Azure Pipelines",
            Self::BitbucketPipelines => "Bitbucket Pipelines",
            Self::Drone => "Drone CI",
            Self::Jenkins => "Jenkins",
            Self::Unknown => "Unknown",
        }
    }

    pub fn api_key(self) -> Option<&'static str> {
        match self {
            Self::GitHubActions => Some("github_actions"),
            Self::Dockerfile => Some("dockerfile"),
            Self::GitLabCi => Some("gitlab_ci"),
            Self::CircleCi => Some("circleci"),
            Self::Buildkite => Some("buildkite"),
            Self::TravisCi => Some("travis_ci"),
            Self::AzurePipelines => Some("azure_pipelines"),
            Self::BitbucketPipelines => Some("bitbucket_pipelines"),
            Self::Drone => Some("drone"),
            Self::Jenkins => Some("jenkins"),
            Self::Unknown => None,
        }
    }

    #[allow(dead_code)]
    pub fn deterministic_supported(self) -> bool {
        matches!(
            self,
            Self::GitHubActions | Self::CircleCi | Self::GitLabCi | Self::Buildkite
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRelevance {
    AlreadyOptimized,
    HasCaching,
    NoCaching,
    NoOpportunity,
    TooLarge,
}

impl FileRelevance {
    pub fn should_send(self) -> bool {
        matches!(self, Self::HasCaching | Self::NoCaching)
    }

    pub fn status_label(self) -> &'static str {
        match self {
            Self::HasCaching => "has caching, will optimize",
            Self::NoCaching => "no caching, will add",
            Self::AlreadyOptimized => "skipped: already uses BoringCache",
            Self::NoOpportunity => "skipped: no optimization opportunity",
            Self::TooLarge => "skipped: file too large",
        }
    }
}

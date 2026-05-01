use super::detect::{detect_git_context, is_git_disabled_by_env};
use super::normalize::{normalize_ref, shorten_sha};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitContext {
    pub pr_number: Option<u32>,
    pub branch: Option<String>,
    pub base_branch: Option<String>,
    pub default_branch: Option<String>,
    pub commit_sha: Option<String>,
}

impl GitContext {
    pub fn detect() -> Self {
        Self::detect_with_path(None)
    }

    pub fn detect_with_path(path_hint: Option<&str>) -> Self {
        if is_git_disabled_by_env() {
            return Self::default();
        }

        detect_git_context(path_hint)
    }

    pub fn has_context(&self) -> bool {
        self.pr_number.is_some()
            || self.branch.is_some()
            || self.base_branch.is_some()
            || self.default_branch.is_some()
            || self.commit_sha.is_some()
    }

    pub fn branch_slug(&self) -> Option<String> {
        self.branch.as_ref().map(|branch| normalize_ref(branch))
    }

    pub fn default_branch_slug(&self) -> Option<String> {
        self.default_branch
            .as_ref()
            .map(|branch| normalize_ref(branch))
    }

    pub fn base_branch_slug(&self) -> Option<String> {
        self.base_branch
            .as_ref()
            .map(|branch| normalize_ref(branch))
    }

    pub fn commit_slug(&self) -> Option<String> {
        self.commit_sha.as_ref().map(|sha| shorten_sha(sha))
    }
}

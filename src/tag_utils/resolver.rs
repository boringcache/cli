use anyhow::Result;

use crate::git::GitContext;
use crate::platform::Platform;

use super::platform::apply_platform_to_tag_with_instance;
use super::validation::validate_tag;

#[derive(Debug, Clone)]
pub struct TagResolver {
    platform: Option<Platform>,
    git_context: GitContext,
    git_enabled: bool,
}

impl TagResolver {
    pub fn new(platform: Option<Platform>, git_context: GitContext, git_enabled: bool) -> Self {
        Self {
            platform,
            git_context,
            git_enabled,
        }
    }

    pub fn effective_save_tag(&self, base_tag: &str) -> Result<String> {
        validate_tag(base_tag)?;

        let tag_with_git = self.tag_with_git_for_save(base_tag);

        let final_tag = apply_platform_to_tag_with_instance(&tag_with_git, self.platform.as_ref());
        validate_tag(&final_tag)?;

        Ok(final_tag)
    }

    pub fn effective_restore_tag(&self, base_tag: &str) -> Result<String> {
        self.effective_save_tag(base_tag)
    }

    fn tag_with_git_for_save(&self, base_tag: &str) -> String {
        if let Some(suffix) = self.git_suffix_for_save(base_tag) {
            format!("{base_tag}{suffix}")
        } else {
            base_tag.to_string()
        }
    }

    fn git_suffix_for_save(&self, base_tag: &str) -> Option<String> {
        if !self.git_enabled
            || tag_has_explicit_channel(base_tag)
            || !self.git_context.has_context()
        {
            return None;
        }

        if let Some(branch_slug) = self.git_context.branch_slug() {
            if is_default_branch(
                &branch_slug,
                self.git_context.default_branch_slug().as_deref(),
            ) {
                return None;
            }
            return Some(format!("-branch-{branch_slug}"));
        }

        if let Some(commit_slug) = self.git_context.commit_slug() {
            return Some(format!("-sha-{commit_slug}"));
        }

        None
    }
}

fn tag_has_explicit_channel(tag: &str) -> bool {
    tag.contains("-branch-")
        || tag.contains("-sha-")
        || tag.ends_with("-main")
        || tag.ends_with("-master")
}

fn is_default_branch(branch_slug: &str, default_branch: Option<&str>) -> bool {
    if let Some(default) = default_branch {
        branch_slug == default
    } else {
        matches!(branch_slug, "main" | "master")
    }
}

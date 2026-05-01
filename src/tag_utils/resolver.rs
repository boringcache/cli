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

#[derive(Debug, Clone, Copy, Default)]
pub struct RestoreTagOptions {
    pub include_pr_tag: bool,
}

impl RestoreTagOptions {
    pub fn from_env() -> Self {
        Self {
            include_pr_tag: crate::config::env_bool("BORINGCACHE_RESTORE_PR_CACHE"),
        }
    }

    #[cfg(test)]
    pub fn include_pr_tag() -> Self {
        Self {
            include_pr_tag: true,
        }
    }
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

    pub fn effective_restore_tags(&self, base_tag: &str) -> Result<Vec<String>> {
        self.effective_restore_tags_with_options(base_tag, RestoreTagOptions::from_env())
    }

    pub fn effective_restore_tags_with_options(
        &self,
        base_tag: &str,
        options: RestoreTagOptions,
    ) -> Result<Vec<String>> {
        validate_tag(base_tag)?;

        let candidates = self.tags_with_git_for_restore(base_tag, options);
        let mut tags = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let final_tag = apply_platform_to_tag_with_instance(&candidate, self.platform.as_ref());
            validate_tag(&final_tag)?;
            if !tags.contains(&final_tag) {
                tags.push(final_tag);
            }
        }

        Ok(tags)
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

        if let Some(pr_number) = self.git_context.pr_number {
            return Some(format!("-pr-{pr_number}"));
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

    fn tags_with_git_for_restore(&self, base_tag: &str, options: RestoreTagOptions) -> Vec<String> {
        if !self.git_enabled
            || tag_has_explicit_channel(base_tag)
            || !self.git_context.has_context()
        {
            return vec![base_tag.to_string()];
        }

        let mut tags = Vec::new();
        if let Some(pr_number) = self.git_context.pr_number {
            if options.include_pr_tag {
                push_unique(&mut tags, format!("{base_tag}-pr-{pr_number}"));
            }
            if let Some(base_branch_slug) = self.git_context.base_branch_slug()
                && is_known_non_default_branch(
                    &base_branch_slug,
                    self.git_context.default_branch_slug().as_deref(),
                )
            {
                push_unique(&mut tags, format!("{base_tag}-branch-{base_branch_slug}"));
            }
            push_unique(&mut tags, base_tag.to_string());
            return tags;
        }

        if let Some(branch_slug) = self.git_context.branch_slug() {
            if !is_default_branch(
                &branch_slug,
                self.git_context.default_branch_slug().as_deref(),
            ) {
                push_unique(&mut tags, format!("{base_tag}-branch-{branch_slug}"));
            }
            push_unique(&mut tags, base_tag.to_string());
            return tags;
        }

        if let Some(commit_slug) = self.git_context.commit_slug() {
            push_unique(&mut tags, format!("{base_tag}-sha-{commit_slug}"));
            push_unique(&mut tags, base_tag.to_string());
            return tags;
        }

        vec![base_tag.to_string()]
    }
}

fn tag_has_explicit_channel(tag: &str) -> bool {
    tag.contains("-branch-")
        || tag.contains("-pr-")
        || tag.contains("-sha-")
        || tag.ends_with("-main")
        || tag.ends_with("-master")
}

fn push_unique(tags: &mut Vec<String>, tag: String) {
    if !tags.contains(&tag) {
        tags.push(tag);
    }
}

fn is_default_branch(branch_slug: &str, default_branch: Option<&str>) -> bool {
    if let Some(default) = default_branch {
        branch_slug == default
    } else {
        matches!(branch_slug, "main" | "master")
    }
}

fn is_known_non_default_branch(branch_slug: &str, default_branch: Option<&str>) -> bool {
    default_branch.is_some_and(|default| branch_slug != default)
}

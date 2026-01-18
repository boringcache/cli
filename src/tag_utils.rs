use anyhow::Result;

use crate::git::GitContext;

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    if tag.len() > 128 {
        anyhow::bail!("Tag '{}' is too long (max 128 characters)", tag);
    }

    let valid_chars = tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));

    if !valid_chars {
        anyhow::bail!(
            "Tag '{}' contains invalid characters. Only alphanumeric characters, dots (.), dashes (-), and underscores (_) are allowed",
            tag
        );
    }

    if tag.starts_with('.') || tag.starts_with('-') {
        anyhow::bail!("Tag '{}' cannot start with '.' or '-'", tag);
    }

    if tag.ends_with('.') || tag.ends_with('-') {
        anyhow::bail!("Tag '{}' cannot end with '.' or '-'", tag);
    }

    if tag.contains("..") {
        anyhow::bail!("Tag '{}' cannot contain consecutive dots (..)", tag);
    }

    Ok(())
}

/// Apply platform detection and tag transformation logic consistently across all commands
/// Performance optimized: only detects platform once when needed
#[inline]
pub fn apply_platform_to_tag(tag: &str, no_platform: bool) -> anyhow::Result<String> {
    if no_platform {
        Ok(tag.to_string())
    } else {
        let platform = crate::platform::Platform::detect()?;
        Ok(platform.append_to_tag(tag))
    }
}

/// Apply platform suffix logic with optional platform instance (for performance when called multiple times)
/// Performance optimized: avoids redundant platform detection in batch operations
#[inline]
pub fn apply_platform_to_tag_with_instance(
    tag: &str,
    platform_option: Option<&crate::platform::Platform>,
) -> String {
    if let Some(platform) = platform_option {
        platform.append_to_tag(tag)
    } else {
        tag.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct TagResolver {
    platform: Option<crate::platform::Platform>,
    git_context: GitContext,
    git_enabled: bool,
}

impl TagResolver {
    pub fn new(
        platform: Option<crate::platform::Platform>,
        git_context: GitContext,
        git_enabled: bool,
    ) -> Self {
        Self {
            platform,
            git_context,
            git_enabled,
        }
    }

    pub fn effective_save_tag(&self, base_tag: &str) -> Result<String> {
        validate_tag(base_tag)?;

        let tag_with_git = if let Some(suffix) = self.git_suffix_for_save(base_tag) {
            format!("{base_tag}{suffix}")
        } else {
            base_tag.to_string()
        };

        let final_tag = apply_platform_to_tag_with_instance(&tag_with_git, self.platform.as_ref());
        validate_tag(&final_tag)?;

        Ok(final_tag)
    }

    pub fn restore_tag_candidates(&self, base_tag: &str) -> Vec<String> {
        match self.effective_save_tag(base_tag) {
            Ok(tag) => vec![tag],
            Err(_) => vec![base_tag.to_string()],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::GitContext;
    use crate::platform::Platform;

    #[test]
    fn test_tag_validation() {
        assert!(validate_tag("ruby-3.4.4").is_ok());
        assert!(validate_tag("node_18.0.0").is_ok());
        assert!(validate_tag("deps.cache").is_ok());
        assert!(validate_tag("valid-tag_123.test").is_ok());

        assert!(validate_tag("").is_err());
        assert!(validate_tag("tag with spaces").is_err());
        assert!(validate_tag("tag:with:colons").is_err());
        assert!(validate_tag("tag@with@ats").is_err());
        assert!(validate_tag(".starts-with-dot").is_err());
        assert!(validate_tag("-starts-with-dash").is_err());
        assert!(validate_tag("ends-with-dot.").is_err());
        assert!(validate_tag("ends-with-dash-").is_err());
        assert!(validate_tag("has..consecutive..dots").is_err());
        assert!(validate_tag(&"a".repeat(129)).is_err());
    }

    fn make_platform() -> Platform {
        Platform::new_for_testing("linux", "x86_64", Some("ubuntu"), Some("22"))
    }

    #[test]
    fn git_branch_suffix_applied() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems-branch-feature-x-ubuntu-22-x86_64");
    }

    #[test]
    fn git_branch_suffix_when_not_pr() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems-branch-feature-x-ubuntu-22-x86_64");
    }

    #[test]
    fn main_branch_keeps_base_tag() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems");
    }

    #[test]
    fn explicit_channel_skips_git_suffix() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: Some(42),
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = resolver.effective_save_tag("gems-main").unwrap();
        assert_eq!(tag, "gems-main");
    }

    #[test]
    fn restore_candidates_use_explicit_git_tag() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(
            candidates,
            vec!["gems-branch-feature-x-ubuntu-22-x86_64".to_string()]
        );
    }

    #[test]
    fn no_git_flag_disables_suffixes_for_restore() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            false,
        );

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems");

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems".to_string()]);
    }

    #[test]
    fn branch_restore_does_not_fallback() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/login".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(
            candidates,
            vec!["gems-branch-feature-login-ubuntu-22-x86_64".to_string()]
        );
    }

    #[test]
    fn no_git_context_keeps_base_tag() {
        let resolver = TagResolver::new(None, GitContext::default(), true);

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems");

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems".to_string()]);
    }

    #[test]
    fn commit_slug_used_when_branch_missing() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: None,
                default_branch: Some("main".to_string()),
                commit_sha: Some("abcdef1234567890".to_string()),
            },
            true,
        );

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems-sha-abcdef123456-ubuntu-22-x86_64");

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(
            candidates,
            vec!["gems-sha-abcdef123456-ubuntu-22-x86_64".to_string()]
        );
    }

    #[test]
    fn non_main_default_branch_uses_base() {
        let resolver = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("develop".to_string()),
                default_branch: Some("develop".to_string()),
                commit_sha: None,
            },
            true,
        );

        let tag = resolver.effective_save_tag("gems").unwrap();
        assert_eq!(tag, "gems");

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems".to_string()]);
    }

    #[test]
    fn feature_branch_with_non_main_default_branch() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("develop".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(
            candidates,
            vec!["gems-branch-feature-x-ubuntu-22-x86_64".to_string()]
        );
    }
}

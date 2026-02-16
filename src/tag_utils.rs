use anyhow::Result;

use crate::git::GitContext;

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    Ok(())
}

#[inline]
pub fn apply_platform_to_tag(tag: &str, no_platform: bool) -> anyhow::Result<String> {
    if no_platform {
        Ok(tag.to_string())
    } else {
        let platform = crate::platform::Platform::detect()?;
        Ok(platform.append_to_tag(tag))
    }
}

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
        let mut candidates = Vec::new();

        if let Ok(tag) = self.effective_save_tag(base_tag) {
            candidates.push(tag);
        }

        if self.git_enabled && !self.is_on_default_branch() {
            let fallback_tag =
                apply_platform_to_tag_with_instance(base_tag, self.platform.as_ref());
            if validate_tag(&fallback_tag).is_ok() && !candidates.contains(&fallback_tag) {
                candidates.push(fallback_tag);
            }
        }

        if candidates.is_empty() {
            candidates.push(base_tag.to_string());
        }

        candidates
    }

    fn is_on_default_branch(&self) -> bool {
        if let Some(branch_slug) = self.git_context.branch_slug() {
            is_default_branch(
                &branch_slug,
                self.git_context.default_branch_slug().as_deref(),
            )
        } else {
            false
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
        // CLI only checks presence — all other rules are server-side
        assert!(validate_tag("ruby-3.4.4").is_ok());
        assert!(validate_tag("node_18.0.0").is_ok());
        assert!(validate_tag("deps.cache").is_ok());
        assert!(validate_tag("valid-tag_123.test").is_ok());
        assert!(validate_tag(&"a".repeat(200)).is_ok());
        assert!(validate_tag("tag with spaces").is_ok());
        assert!(validate_tag(".starts-with-dot").is_ok());

        assert!(validate_tag("").is_err());
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
    fn restore_candidates_with_fallback_to_default_branch() {
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
            vec![
                "gems-branch-feature-x-ubuntu-22-x86_64".to_string(),
                "gems-ubuntu-22-x86_64".to_string(),
            ]
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
    fn branch_restore_falls_back_to_default_branch() {
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
            vec![
                "gems-branch-feature-login-ubuntu-22-x86_64".to_string(),
                "gems-ubuntu-22-x86_64".to_string(),
            ]
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
            vec![
                "gems-sha-abcdef123456-ubuntu-22-x86_64".to_string(),
                "gems-ubuntu-22-x86_64".to_string(),
            ]
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
            vec![
                "gems-branch-feature-x-ubuntu-22-x86_64".to_string(),
                "gems-ubuntu-22-x86_64".to_string(),
            ]
        );
    }

    #[test]
    fn default_branch_no_fallback_needed() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems-ubuntu-22-x86_64".to_string()]);
    }

    #[test]
    fn fallback_not_duplicated_when_on_default_branch() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("develop".to_string()),
                default_branch: Some("develop".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates, vec!["gems-ubuntu-22-x86_64".to_string()]);
    }

    #[test]
    fn fallback_without_platform() {
        let resolver = TagResolver::new(
            None,
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
            vec!["gems-branch-feature-x".to_string(), "gems".to_string(),]
        );
    }

    #[test]
    fn long_tag_resolves_with_suffixes() {
        let base_tag = "a".repeat(200);
        assert!(validate_tag(&base_tag).is_ok());

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

        let candidates = resolver.restore_tag_candidates(&base_tag);
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].contains("-branch-feature-x"));
        assert!(!candidates[1].contains("-branch-"));
    }

    #[test]
    fn fallback_order_branch_first_then_default() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/checkout".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("deps");
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].contains("-branch-feature-checkout"));
        assert!(!candidates[1].contains("-branch-"));
    }

    #[test]
    fn multiple_feature_branches_each_fallback_to_same_default() {
        let platform = make_platform();

        let resolver_a = TagResolver::new(
            Some(platform.clone()),
            GitContext {
                pr_number: None,
                branch: Some("feature/a".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let resolver_b = TagResolver::new(
            Some(platform.clone()),
            GitContext {
                pr_number: None,
                branch: Some("feature/b".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates_a = resolver_a.restore_tag_candidates("gems");
        let candidates_b = resolver_b.restore_tag_candidates("gems");

        assert_ne!(candidates_a[0], candidates_b[0]);
        assert_eq!(candidates_a[1], candidates_b[1]);
        assert_eq!(candidates_a[1], "gems-ubuntu-22-x86_64");
    }

    #[test]
    fn explicit_channel_tag_no_fallback() {
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

        let candidates = resolver.restore_tag_candidates("gems-main");
        assert_eq!(candidates, vec!["gems-main-ubuntu-22-x86_64".to_string()]);
    }

    #[test]
    fn git_disabled_no_fallback() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            false,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems-ubuntu-22-x86_64".to_string()]);
    }

    #[test]
    fn pr_branch_falls_back_to_default() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: Some(123),
                branch: Some("feature/pr-123".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(
            candidates,
            vec![
                "gems-branch-feature-pr-123-ubuntu-22-x86_64".to_string(),
                "gems-ubuntu-22-x86_64".to_string(),
            ]
        );
    }

    #[test]
    fn deeply_nested_branch_falls_back() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("feature/team/project/task-123".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].contains("-branch-feature-team-project-task-123"));
        assert_eq!(candidates[1], "gems-ubuntu-22-x86_64");
    }

    #[test]
    fn master_as_default_branch() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("master".to_string()),
                default_branch: Some("master".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems-ubuntu-22-x86_64".to_string()]);
    }

    #[test]
    fn feature_off_master_falls_back() {
        let resolver = TagResolver::new(
            Some(make_platform()),
            GitContext {
                pr_number: None,
                branch: Some("hotfix/urgent".to_string()),
                default_branch: Some("master".to_string()),
                commit_sha: None,
            },
            true,
        );

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(
            candidates,
            vec![
                "gems-branch-hotfix-urgent-ubuntu-22-x86_64".to_string(),
                "gems-ubuntu-22-x86_64".to_string(),
            ]
        );
    }

    #[test]
    fn no_git_context_single_candidate() {
        let resolver = TagResolver::new(Some(make_platform()), GitContext::default(), true);

        let candidates = resolver.restore_tag_candidates("gems");
        assert_eq!(candidates, vec!["gems-ubuntu-22-x86_64".to_string()]);
    }

    #[test]
    fn is_on_default_branch_helper() {
        let on_main = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("main".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );
        assert!(on_main.is_on_default_branch());

        let on_feature = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: Some("feature/x".to_string()),
                default_branch: Some("main".to_string()),
                commit_sha: None,
            },
            true,
        );
        assert!(!on_feature.is_on_default_branch());

        let no_branch = TagResolver::new(
            None,
            GitContext {
                pr_number: None,
                branch: None,
                default_branch: Some("main".to_string()),
                commit_sha: Some("abc123".to_string()),
            },
            true,
        );
        assert!(!no_branch.is_on_default_branch());
    }
}

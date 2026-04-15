use super::{TagResolver, validate_tag};
use crate::git::GitContext;
use crate::platform::Platform;

#[test]
fn test_tag_validation() {
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

fn family_tag(tag: &str) -> String {
    format!("{tag}-linux-amd64")
}

fn legacy_tag(tag: &str) -> String {
    format!("{tag}-ubuntu-22-x86_64")
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
    assert_eq!(tag, family_tag("gems-branch-feature-x"));
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
    assert_eq!(tag, family_tag("gems-branch-feature-x"));
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
            family_tag("gems-branch-feature-x"),
            legacy_tag("gems-branch-feature-x"),
            family_tag("gems"),
            legacy_tag("gems"),
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
            family_tag("gems-branch-feature-login"),
            legacy_tag("gems-branch-feature-login"),
            family_tag("gems"),
            legacy_tag("gems"),
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
    assert_eq!(tag, family_tag("gems-sha-abcdef123456"));

    let candidates = resolver.restore_tag_candidates("gems");
    assert_eq!(
        candidates,
        vec![
            family_tag("gems-sha-abcdef123456"),
            legacy_tag("gems-sha-abcdef123456"),
            family_tag("gems"),
            legacy_tag("gems"),
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
            family_tag("gems-branch-feature-x"),
            legacy_tag("gems-branch-feature-x"),
            family_tag("gems"),
            legacy_tag("gems"),
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
    assert_eq!(candidates, vec![family_tag("gems"), legacy_tag("gems")]);
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
    assert_eq!(candidates, vec![family_tag("gems"), legacy_tag("gems")]);
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
    assert_eq!(candidates.len(), 4);
    assert!(candidates[0].contains("-branch-feature-x"));
    assert!(candidates[1].contains("-branch-feature-x"));
    assert!(!candidates[2].contains("-branch-"));
    assert!(!candidates[3].contains("-branch-"));
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
    assert_eq!(candidates.len(), 4);
    assert!(candidates[0].contains("-branch-feature-checkout"));
    assert!(candidates[1].contains("-branch-feature-checkout"));
    assert!(!candidates[2].contains("-branch-"));
    assert!(!candidates[3].contains("-branch-"));
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
    assert_eq!(candidates_a[2], candidates_b[2]);
    assert_eq!(candidates_a[3], candidates_b[3]);
    assert_eq!(candidates_a[2], family_tag("gems"));
    assert_eq!(candidates_a[3], legacy_tag("gems"));
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
    assert_eq!(
        candidates,
        vec![family_tag("gems-main"), legacy_tag("gems-main")]
    );
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
    assert_eq!(candidates, vec![family_tag("gems"), legacy_tag("gems")]);
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
            family_tag("gems-branch-feature-pr-123"),
            legacy_tag("gems-branch-feature-pr-123"),
            family_tag("gems"),
            legacy_tag("gems"),
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
    assert_eq!(candidates.len(), 4);
    assert!(candidates[0].contains("-branch-feature-team-project-task-123"));
    assert_eq!(candidates[2], family_tag("gems"));
    assert_eq!(candidates[3], legacy_tag("gems"));
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
    assert_eq!(candidates, vec![family_tag("gems"), legacy_tag("gems")]);
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
            family_tag("gems-branch-hotfix-urgent"),
            legacy_tag("gems-branch-hotfix-urgent"),
            family_tag("gems"),
            legacy_tag("gems"),
        ]
    );
}

#[test]
fn no_git_context_single_candidate() {
    let resolver = TagResolver::new(Some(make_platform()), GitContext::default(), true);

    let candidates = resolver.restore_tag_candidates("gems");
    assert_eq!(candidates, vec![family_tag("gems"), legacy_tag("gems")]);
}

#[test]
fn explicit_platform_suffix_skips_migration_candidates() {
    let resolver = TagResolver::new(Some(make_platform()), GitContext::default(), true);

    let candidates = resolver.restore_tag_candidates("gems-ubuntu-22-x86_64");
    assert_eq!(candidates, vec!["gems-ubuntu-22-x86_64".to_string()]);
}

#[test]
fn macos_restore_candidates_include_versioned_legacy_suffix() {
    let resolver = TagResolver::new(
        Some(Platform::new_for_testing(
            "macos",
            "arm64",
            Some("darwin"),
            Some("15"),
        )),
        GitContext::default(),
        true,
    );

    let candidates = resolver.restore_tag_candidates("gems");
    assert_eq!(candidates, vec!["gems-macos-15-arm64".to_string()]);
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

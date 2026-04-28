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
    format!("{tag}-ubuntu-22-x86_64")
}

fn git_context(
    branch: Option<&str>,
    default_branch: Option<&str>,
    commit_sha: Option<&str>,
) -> GitContext {
    GitContext {
        pr_number: None,
        branch: branch.map(ToOwned::to_owned),
        default_branch: default_branch.map(ToOwned::to_owned),
        commit_sha: commit_sha.map(ToOwned::to_owned),
    }
}

#[test]
fn git_branch_suffix_applied_to_save_tags() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some("feature/x"), Some("main"), None),
        true,
    );

    let tag = resolver.effective_save_tag("gems").unwrap();
    assert_eq!(tag, family_tag("gems-branch-feature-x"));
}

#[test]
fn restore_uses_single_effective_tag_for_feature_branch() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some("feature/login"), Some("main"), None),
        true,
    );

    let tag = resolver.effective_restore_tag("gems").unwrap();
    assert_eq!(tag, family_tag("gems-branch-feature-login"));
    assert_ne!(tag, family_tag("gems"));
}

#[test]
fn no_git_flag_disables_suffixes_for_save_and_restore() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some("feature/x"), Some("main"), None),
        false,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems")
    );
    assert_eq!(
        resolver.effective_restore_tag("gems").unwrap(),
        family_tag("gems")
    );
}

#[test]
fn default_branch_keeps_base_tag_before_platform_suffix() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some("main"), Some("main"), None),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems")
    );
    assert_eq!(
        resolver.effective_restore_tag("gems").unwrap(),
        family_tag("gems")
    );
}

#[test]
fn non_main_default_branch_keeps_base_tag() {
    let resolver = TagResolver::new(
        None,
        git_context(Some("develop"), Some("develop"), None),
        true,
    );

    assert_eq!(resolver.effective_save_tag("gems").unwrap(), "gems");
    assert_eq!(resolver.effective_restore_tag("gems").unwrap(), "gems");
}

#[test]
fn explicit_channel_skips_git_suffix() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some("feature/x"), Some("main"), None),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems-main").unwrap(),
        family_tag("gems-main")
    );
    assert_eq!(
        resolver.effective_restore_tag("gems-main").unwrap(),
        family_tag("gems-main")
    );
}

#[test]
fn commit_slug_used_when_branch_missing() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, Some("main"), Some("abcdef1234567890")),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems-sha-abcdef123456")
    );
    assert_eq!(
        resolver.effective_restore_tag("gems").unwrap(),
        family_tag("gems-sha-abcdef123456")
    );
}

#[test]
fn no_git_context_keeps_base_tag() {
    let resolver = TagResolver::new(None, GitContext::default(), true);

    assert_eq!(resolver.effective_save_tag("gems").unwrap(), "gems");
    assert_eq!(resolver.effective_restore_tag("gems").unwrap(), "gems");
}

#[test]
fn deeply_nested_branch_is_normalized_once() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some("feature/team/project/task-123"), Some("main"), None),
        true,
    );

    let tag = resolver.effective_restore_tag("gems").unwrap();
    assert_eq!(tag, family_tag("gems-branch-feature-team-project-task-123"));
}

#[test]
fn explicit_platform_suffix_is_not_duplicated() {
    let resolver = TagResolver::new(Some(make_platform()), GitContext::default(), true);

    assert_eq!(
        resolver
            .effective_restore_tag("gems-ubuntu-22-x86_64")
            .unwrap(),
        "gems-ubuntu-22-x86_64"
    );
}

#[test]
fn macos_restore_tag_uses_versioned_suffix() {
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

    assert_eq!(
        resolver.effective_restore_tag("gems").unwrap(),
        "gems-macos-15-arm64"
    );
}

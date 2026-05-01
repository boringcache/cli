use super::{TagResolver, validate_tag};
use crate::git::GitContext;
use crate::platform::Platform;
use crate::tag_utils::RestoreTagOptions;
use crate::test_env;

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

fn first_restore_tag(resolver: &TagResolver, base_tag: &str) -> String {
    resolver
        .effective_restore_tags(base_tag)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
}

fn git_context(
    pr_number: Option<u32>,
    branch: Option<&str>,
    base_branch: Option<&str>,
    default_branch: Option<&str>,
    commit_sha: Option<&str>,
) -> GitContext {
    GitContext {
        pr_number,
        branch: branch.map(ToOwned::to_owned),
        base_branch: base_branch.map(ToOwned::to_owned),
        default_branch: default_branch.map(ToOwned::to_owned),
        commit_sha: commit_sha.map(ToOwned::to_owned),
    }
}

#[test]
fn git_branch_suffix_applied_to_save_tags() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, Some("feature/x"), None, Some("main"), None),
        true,
    );

    let tag = resolver.effective_save_tag("gems").unwrap();
    assert_eq!(tag, family_tag("gems-branch-feature-x"));
}

#[test]
fn restore_tries_branch_then_default_for_feature_branch() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, Some("feature/login"), None, Some("main"), None),
        true,
    );

    assert_eq!(
        resolver.effective_restore_tags("gems").unwrap(),
        vec![family_tag("gems-branch-feature-login"), family_tag("gems")]
    );
    assert_eq!(
        first_restore_tag(&resolver, "gems"),
        family_tag("gems-branch-feature-login")
    );
}

#[test]
fn no_git_flag_disables_suffixes_for_save_and_restore() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, Some("feature/x"), None, Some("main"), None),
        false,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems")
    );
    assert_eq!(first_restore_tag(&resolver, "gems"), family_tag("gems"));
}

#[test]
fn default_branch_keeps_base_tag_before_platform_suffix() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, Some("main"), None, Some("main"), None),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems")
    );
    assert_eq!(
        resolver.effective_restore_tags("gems").unwrap(),
        vec![family_tag("gems")]
    );
}

#[test]
fn non_main_default_branch_keeps_base_tag() {
    let resolver = TagResolver::new(
        None,
        git_context(None, Some("develop"), None, Some("develop"), None),
        true,
    );

    assert_eq!(resolver.effective_save_tag("gems").unwrap(), "gems");
    assert_eq!(first_restore_tag(&resolver, "gems"), "gems");
}

#[test]
fn explicit_channel_skips_git_suffix() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, Some("feature/x"), None, Some("main"), None),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems-main").unwrap(),
        family_tag("gems-main")
    );
    assert_eq!(
        first_restore_tag(&resolver, "gems-main"),
        family_tag("gems-main")
    );
}

#[test]
fn commit_slug_used_when_branch_missing() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(None, None, None, Some("main"), Some("abcdef1234567890")),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems-sha-abcdef123456")
    );
    assert_eq!(
        resolver.effective_restore_tags("gems").unwrap(),
        vec![family_tag("gems-sha-abcdef123456"), family_tag("gems")]
    );
}

#[test]
fn no_git_context_keeps_base_tag() {
    let resolver = TagResolver::new(None, GitContext::default(), true);

    assert_eq!(resolver.effective_save_tag("gems").unwrap(), "gems");
    assert_eq!(first_restore_tag(&resolver, "gems"), "gems");
}

#[test]
fn deeply_nested_branch_is_normalized_once() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(
            None,
            Some("feature/team/project/task-123"),
            None,
            Some("main"),
            None,
        ),
        true,
    );

    let tag = first_restore_tag(&resolver, "gems");
    assert_eq!(tag, family_tag("gems-branch-feature-team-project-task-123"));
}

#[test]
fn pull_request_restore_skips_head_branch_by_default() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(
            Some(42),
            Some("feature/cache"),
            Some("main"),
            Some("main"),
            None,
        ),
        true,
    );

    assert_eq!(
        resolver.effective_restore_tags("gems").unwrap(),
        vec![family_tag("gems")]
    );
}

#[test]
fn pull_request_restore_can_try_pr_scope_before_base_default() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(
            Some(42),
            Some("feature/cache"),
            Some("main"),
            Some("main"),
            None,
        ),
        true,
    );

    assert_eq!(
        resolver
            .effective_restore_tags_with_options("gems", RestoreTagOptions::include_pr_tag())
            .unwrap(),
        vec![family_tag("gems-pr-42"), family_tag("gems")]
    );
}

#[test]
fn restore_pr_cache_env_controls_pr_restore_reads() {
    let _guard = test_env::lock();
    test_env::remove_var("BORINGCACHE_SAVE_ON_PULL_REQUEST");
    test_env::remove_var("BORINGCACHE_RESTORE_PR_CACHE");

    test_env::set_var("BORINGCACHE_SAVE_ON_PULL_REQUEST", "1");
    assert!(!RestoreTagOptions::from_env().include_pr_tag);

    test_env::set_var("BORINGCACHE_RESTORE_PR_CACHE", "1");
    assert!(RestoreTagOptions::from_env().include_pr_tag);

    test_env::remove_var("BORINGCACHE_SAVE_ON_PULL_REQUEST");
    test_env::remove_var("BORINGCACHE_RESTORE_PR_CACHE");
}

#[test]
fn pull_request_restore_includes_non_default_base_before_default() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(
            Some(42),
            Some("feature/cache"),
            Some("release/1"),
            Some("main"),
            None,
        ),
        true,
    );

    assert_eq!(
        resolver
            .effective_restore_tags_with_options("gems", RestoreTagOptions::include_pr_tag())
            .unwrap(),
        vec![
            family_tag("gems-pr-42"),
            family_tag("gems-branch-release-1"),
            family_tag("gems")
        ]
    );
}

#[test]
fn pull_request_restore_skips_base_branch_when_default_branch_is_unknown() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(Some(42), Some("feature/cache"), Some("main"), None, None),
        true,
    );

    assert_eq!(
        resolver
            .effective_restore_tags_with_options("gems", RestoreTagOptions::include_pr_tag())
            .unwrap(),
        vec![family_tag("gems-pr-42"), family_tag("gems")]
    );
}

#[test]
fn pull_request_save_uses_pr_scope_instead_of_head_branch() {
    let resolver = TagResolver::new(
        Some(make_platform()),
        git_context(
            Some(42),
            Some("feature/cache"),
            Some("main"),
            Some("main"),
            None,
        ),
        true,
    );

    assert_eq!(
        resolver.effective_save_tag("gems").unwrap(),
        family_tag("gems-pr-42")
    );
}

#[test]
fn explicit_platform_suffix_is_not_duplicated() {
    let resolver = TagResolver::new(Some(make_platform()), GitContext::default(), true);

    assert_eq!(
        first_restore_tag(&resolver, "gems-ubuntu-22-x86_64"),
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

    assert_eq!(first_restore_tag(&resolver, "gems"), "gems-macos-15-arm64");
}

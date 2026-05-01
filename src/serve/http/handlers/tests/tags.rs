use super::*;

#[test]
fn scoped_save_tag_applies_git_suffix() {
    let resolver = TagResolver::new(
        None,
        GitContext {
            pr_number: None,
            branch: Some("feature/x".to_string()),
            base_branch: None,
            default_branch: Some("main".to_string()),
            commit_sha: None,
        },
        true,
    );

    let tag = scoped_save_tag(
        &resolver,
        &["buildcache".to_string()],
        "registry-root",
        "buildkit-cache",
        "main",
    )
    .unwrap();
    assert_eq!(
        tag,
        ref_tag_for_input("buildcache:buildkit-cache:main-branch-feature-x")
    );
}

#[test]
fn scoped_restore_tags_use_human_root_and_legacy_compat_tags() {
    let resolver = TagResolver::new(
        None,
        GitContext {
            pr_number: None,
            branch: Some("feature/x".to_string()),
            base_branch: None,
            default_branch: Some("main".to_string()),
            commit_sha: None,
        },
        true,
    );

    let tags = scoped_restore_tags(
        &resolver,
        &["buildcache".to_string()],
        "registry-root",
        "buildkit-cache",
        "main",
    );
    assert_eq!(
        tags,
        vec![
            ref_tag_for_input("buildcache:buildkit-cache:main-branch-feature-x"),
            legacy_ref_tag_for_input("registry-root:buildkit-cache:main-branch-feature-x"),
            ref_tag_for_input("buildcache:buildkit-cache:main"),
            legacy_ref_tag_for_input("registry-root:buildkit-cache:main"),
        ]
    );
}

#[test]
fn scoped_restore_tags_without_root_use_readable_and_legacy_unscoped_tags() {
    let resolver = TagResolver::new(
        None,
        GitContext {
            pr_number: None,
            branch: Some("feature/x".to_string()),
            base_branch: None,
            default_branch: Some("main".to_string()),
            commit_sha: None,
        },
        true,
    );

    let tags = scoped_restore_tags(&resolver, &[], "", "buildkit-cache", "main");
    assert_eq!(
        tags,
        vec![
            ref_tag_for_input("buildkit-cache:main-branch-feature-x"),
            legacy_ref_tag_for_input("buildkit-cache:main-branch-feature-x"),
            ref_tag_for_input("buildkit-cache:main"),
            legacy_ref_tag_for_input("buildkit-cache:main"),
        ]
    );
}

#[test]
fn scoped_save_tag_on_default_branch_uses_base() {
    let resolver = TagResolver::new(
        None,
        GitContext {
            pr_number: None,
            branch: Some("main".to_string()),
            base_branch: None,
            default_branch: Some("main".to_string()),
            commit_sha: None,
        },
        true,
    );

    let tag = scoped_save_tag(
        &resolver,
        &["buildcache".to_string()],
        "registry-root",
        "buildkit-cache",
        "main",
    )
    .unwrap();
    assert_eq!(tag, ref_tag_for_input("buildcache:buildkit-cache:main"));
}

#[test]
fn scoped_save_tag_applies_platform_suffix() {
    let resolver = TagResolver::new(
        Some(Platform::new_for_testing(
            "linux",
            "x86_64",
            Some("ubuntu"),
            Some("22"),
        )),
        GitContext::default(),
        false,
    );

    let tag = scoped_save_tag(
        &resolver,
        &["buildcache".to_string()],
        "registry-root",
        "buildkit-cache",
        "main",
    )
    .unwrap();
    assert_eq!(
        tag,
        ref_tag_for_input("buildcache:buildkit-cache:main-ubuntu-22-x86_64")
    );
}

#[test]
fn alias_tags_include_digest_and_human_alias_when_distinct() {
    let tags = alias_tags_for_manifest(
        "oci_ref_primary",
        "sha256:abc123",
        Some("posthog-build:pr-123"),
        &["posthog-docker-build".to_string()],
        &[],
    );
    assert_eq!(
        tags,
        vec![
            AliasBinding {
                tag: "oci_digest_abc123".to_string(),
                write_scope_tag: Some("posthog-build:pr-123".to_string()),
                required: false
            },
            AliasBinding {
                tag: "posthog-docker-build".to_string(),
                write_scope_tag: None,
                required: true
            }
        ]
    );
}

#[test]
fn alias_tags_skip_primary_and_deduplicate() {
    let tags = alias_tags_for_manifest(
        "oci_digest_abc123",
        "sha256:abc123",
        Some("posthog-build:pr-123"),
        &["oci_digest_abc123".to_string()],
        &[],
    );
    assert!(tags.is_empty());
}

#[test]
fn alias_tags_include_multiple_human_aliases() {
    let tags = alias_tags_for_manifest(
        "oci_ref_primary",
        "sha256:abc123",
        Some("posthog-build:pr-123"),
        &[
            "posthog-build".to_string(),
            "posthog-stable".to_string(),
            "posthog-build".to_string(),
        ],
        &[],
    );
    assert_eq!(
        tags,
        vec![
            AliasBinding {
                tag: "oci_digest_abc123".to_string(),
                write_scope_tag: Some("posthog-build:pr-123".to_string()),
                required: false
            },
            AliasBinding {
                tag: "posthog-build".to_string(),
                write_scope_tag: None,
                required: true
            },
            AliasBinding {
                tag: "posthog-stable".to_string(),
                write_scope_tag: None,
                required: true
            },
        ]
    );
}

#[test]
fn alias_tags_keep_invalid_human_aliases_best_effort() {
    let tags = alias_tags_for_manifest(
        "oci_ref_primary",
        "sha256:abc123",
        Some("posthog-build:pr-123"),
        &["docker/main".to_string()],
        &[],
    );

    assert_eq!(
        tags,
        vec![
            AliasBinding {
                tag: "oci_digest_abc123".to_string(),
                write_scope_tag: Some("posthog-build:pr-123".to_string()),
                required: false
            },
            AliasBinding {
                tag: "docker/main".to_string(),
                write_scope_tag: None,
                required: false
            },
        ]
    );
}

#[test]
fn alias_tags_include_additional_aliases() {
    let tags = alias_tags_for_manifest(
        "oci_digest_abc123",
        "sha256:abc123",
        Some("posthog-build:pr-123"),
        &["posthog-build".to_string()],
        &[
            AliasBinding {
                tag: "oci_ref_latest".to_string(),
                write_scope_tag: Some("posthog-build:latest".to_string()),
                required: false,
            },
            AliasBinding {
                tag: "posthog-build".to_string(),
                write_scope_tag: None,
                required: true,
            },
            AliasBinding {
                tag: "oci_ref_latest".to_string(),
                write_scope_tag: Some("posthog-build:latest".to_string()),
                required: false,
            },
        ],
    );
    assert_eq!(
        tags,
        vec![
            AliasBinding {
                tag: "posthog-build".to_string(),
                write_scope_tag: None,
                required: true
            },
            AliasBinding {
                tag: "oci_ref_latest".to_string(),
                write_scope_tag: Some("posthog-build:latest".to_string()),
                required: false
            }
        ]
    );
}

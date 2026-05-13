use super::*;
use crate::serve::http::oci_tags::scoped_write_scope_tag;

#[test]
fn scoped_save_tag_keeps_human_reference_first_class() {
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
        "primary-cache",
        "buildkit-cache",
        "posthog-run-main-ubuntu-24-x86_64",
    )
    .unwrap();
    assert_eq!(tag, "posthog-run-main-ubuntu-24-x86_64");
}

#[test]
fn scoped_restore_tags_use_human_reference_directly() {
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
        "primary-cache",
        "buildkit-cache",
        "posthog-run-main-ubuntu-24-x86_64",
    );
    assert_eq!(tags, vec!["posthog-run-main-ubuntu-24-x86_64".to_string()]);
}

#[test]
fn scoped_restore_tags_keep_legacy_ref_shape_only_for_non_human_references() {
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

    let tags = scoped_restore_tags(&resolver, &[], "", "buildkit-cache", "repo/image:main");
    assert_eq!(
        tags,
        vec![
            readable_oci_ref_tag_for_input("buildkit-cache:repo/image:main-branch-feature-x"),
            legacy_oci_ref_tag_for_input("buildkit-cache:repo/image:main-branch-feature-x"),
            readable_oci_ref_tag_for_input("buildkit-cache:repo/image:main"),
            legacy_oci_ref_tag_for_input("buildkit-cache:repo/image:main"),
        ]
    );
}

#[test]
fn scoped_save_tag_on_default_branch_keeps_human_reference() {
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
        "primary-cache",
        "buildkit-cache",
        "docker-main",
    )
    .unwrap();
    assert_eq!(tag, "docker-main");
}

#[test]
fn scoped_write_scope_tag_keeps_human_reference() {
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

    let tag = scoped_write_scope_tag(&resolver, "buildkit-cache", "docker-main").unwrap();
    assert_eq!(tag, "docker-main");
}

#[test]
fn alias_tags_include_human_alias_when_distinct() {
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
                required: true
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
                required: true
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
                required: true
            },
            AliasBinding {
                tag: "docker/main".to_string(),
                write_scope_tag: None,
                required: false
            }
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

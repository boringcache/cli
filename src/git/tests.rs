use super::GitContext;
use super::normalize::normalize_ref;
use crate::test_env;

fn clear_git_env_vars() {
    for var in [
        "BORINGCACHE_DEFAULT_BRANCH",
        "BORINGCACHE_CI_DEFAULT_BRANCH",
        "BORINGCACHE_CI_BASE_REF",
        "BORINGCACHE_CI_PR_NUMBER",
        "BORINGCACHE_GIT_BRANCH",
        "BORINGCACHE_GIT_SHA",
        "GITHUB_ACTIONS",
        "GITHUB_BASE_REF",
        "GITHUB_DEFAULT_BRANCH",
        "GITHUB_EVENT_PATH",
        "GITHUB_HEAD_REF",
        "GITHUB_REF",
        "GITHUB_REF_NAME",
        "GITHUB_SHA",
        "CI",
    ] {
        test_env::remove_var(var);
    }
}

#[test]
fn normalize_ref_sanitizes_characters() {
    assert_eq!(normalize_ref("Feature/ABC-123"), "feature-abc-123");
    assert_eq!(normalize_ref(" release "), "release");
    assert_eq!(normalize_ref(""), "unknown");
}

#[test]
fn detect_local_git_branch_from_directory() {
    let temp = tempfile::tempdir().unwrap();
    let git_dir = temp.path().join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/feature/login").unwrap();

    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
    assert_eq!(ctx.branch.as_deref(), Some("feature-login"));
}

#[test]
fn detect_local_git_from_gitdir_file() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    let dot_git = temp.path().join(".git");
    let actual_git = temp.path().join("nested/gitdir");
    std::fs::create_dir_all(&actual_git).unwrap();
    std::fs::write(actual_git.join("HEAD"), "ref: refs/heads/main").unwrap();
    std::fs::create_dir_all(actual_git.join("refs/remotes/origin")).unwrap();
    std::fs::write(
        actual_git.join("refs/remotes/origin/HEAD"),
        "ref: refs/remotes/origin/main",
    )
    .unwrap();
    std::fs::write(&dot_git, format!("gitdir: {}", actual_git.display())).unwrap();

    clear_git_env_vars();

    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
    assert_eq!(ctx.branch.as_deref(), Some("main"));
    assert_eq!(ctx.default_branch.as_deref(), Some("main"));
}

#[test]
fn detects_default_branch_from_origin_head() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    let git_dir = temp.path().join(".git");
    std::fs::create_dir_all(git_dir.join("refs/remotes/origin")).unwrap();
    std::fs::write(
        git_dir.join("refs/remotes/origin/HEAD"),
        "ref: refs/remotes/origin/develop",
    )
    .unwrap();
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/develop").unwrap();

    clear_git_env_vars();
    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
    assert_eq!(ctx.default_branch.as_deref(), Some("develop"));
}

#[test]
fn missing_origin_head_returns_none() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    let git_dir = temp.path().join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/feature/x").unwrap();

    clear_git_env_vars();
    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
    assert!(ctx.default_branch.is_none());
}

#[test]
fn env_override_wins_for_default_branch() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    let git_dir = temp.path().join(".git");
    std::fs::create_dir_all(git_dir.join("refs/remotes/origin")).unwrap();
    std::fs::write(
        git_dir.join("refs/remotes/origin/HEAD"),
        "ref: refs/remotes/origin/main",
    )
    .unwrap();
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main").unwrap();

    clear_git_env_vars();
    test_env::set_var("BORINGCACHE_DEFAULT_BRANCH", "develop");
    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));

    assert_eq!(ctx.default_branch.as_deref(), Some("develop"));
}

#[test]
fn ci_env_branch_used_when_branch_missing() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    clear_git_env_vars();
    test_env::set_var("GITHUB_HEAD_REF", "feature/ci-branch");
    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));

    assert_eq!(ctx.branch.as_deref(), Some("feature-ci-branch"));
}

#[test]
fn ci_sha_used_when_no_branch() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    clear_git_env_vars();
    test_env::set_var("CI", "true");
    test_env::set_var("GITHUB_SHA", "1234567890abcdef");
    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
    assert_eq!(ctx.commit_slug().as_deref(), Some("1234567890ab"));
}

#[test]
fn ci_pr_context_uses_number_base_and_default_branch() {
    let _guard = test_env::lock();

    let temp = tempfile::tempdir().unwrap();
    clear_git_env_vars();
    test_env::set_var("GITHUB_ACTIONS", "true");
    test_env::set_var("GITHUB_REF", "refs/pull/42/merge");
    test_env::set_var("GITHUB_REF_NAME", "42/merge");
    test_env::set_var("GITHUB_HEAD_REF", "feature/cache");
    test_env::set_var("GITHUB_BASE_REF", "release/1");
    test_env::set_var("GITHUB_DEFAULT_BRANCH", "main");

    let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));

    assert_eq!(ctx.pr_number, Some(42));
    assert_eq!(ctx.branch.as_deref(), Some("feature-cache"));
    assert_eq!(ctx.base_branch.as_deref(), Some("release-1"));
    assert_eq!(ctx.default_branch.as_deref(), Some("main"));
}

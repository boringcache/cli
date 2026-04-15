use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::context::GitContext;
use super::normalize::normalize_ref;

pub fn is_git_disabled_by_env() -> bool {
    if env::var("BORINGCACHE_TEST_MODE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }

    matches!(
        env::var("BORINGCACHE_NO_GIT")
            .ok()
            .map(|v| v.to_ascii_lowercase()),
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on")
    )
}

pub(super) fn detect_git_context(path_hint: Option<&str>) -> GitContext {
    let override_default = env_default_branch();

    let mut context = detect_local_git_context(path_hint).unwrap_or_default();

    if context.branch.is_none() {
        context.branch = detect_ci_branch();
    }

    if override_default.is_some() {
        context.default_branch = override_default;
    }

    if context.commit_sha.is_none() && is_ci_env() {
        context.commit_sha = detect_ci_sha();
    }

    context
}

fn detect_local_git_context(path_hint: Option<&str>) -> Option<GitContext> {
    let start_path = path_hint
        .and_then(|p| {
            let path = Path::new(p);
            if path.exists() {
                if path.is_dir() {
                    Some(path.to_path_buf())
                } else {
                    path.parent().map(|p| p.to_path_buf())
                }
            } else {
                path.parent().map(|p| p.to_path_buf())
            }
        })
        .or_else(|| std::env::current_dir().ok())?;

    let git_dir = find_git_dir(&start_path)?;
    let branch = detect_branch_from_head(&git_dir)?;
    let default_branch = detect_default_branch(&git_dir);

    Some(GitContext {
        pr_number: None,
        branch: Some(branch),
        default_branch,
        commit_sha: None,
    })
}

fn find_git_dir(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();

    loop {
        let candidate = current.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file()
            && let Ok(contents) = fs::read_to_string(&candidate)
            && let Some(rest) = contents.strip_prefix("gitdir:")
        {
            let gitdir = rest.trim();
            let resolved = if Path::new(gitdir).is_absolute() {
                PathBuf::from(gitdir)
            } else {
                current.join(gitdir)
            };
            return Some(resolved);
        }

        if !current.pop() {
            break;
        }
    }

    None
}

fn detect_branch_from_head(git_dir: &Path) -> Option<String> {
    let head_path = git_dir.join("HEAD");
    let contents = fs::read_to_string(head_path).ok()?;
    let head = contents.trim();

    if let Some(rest) = head.strip_prefix("ref:") {
        let reference = rest.trim();
        let branch_ref = reference.strip_prefix("refs/heads/").unwrap_or(reference);
        return Some(normalize_ref(branch_ref));
    }

    None
}

fn detect_default_branch(git_dir: &Path) -> Option<String> {
    let origin_head = git_dir.join("refs/remotes/origin/HEAD");
    if let Ok(contents) = fs::read_to_string(&origin_head)
        && let Some(rest) = contents.trim().strip_prefix("ref:")
    {
        let reference = rest.trim();
        if let Some(branch_name) = reference.rsplit('/').next() {
            return Some(normalize_ref(branch_name));
        }
    }

    None
}

fn env_default_branch() -> Option<String> {
    crate::config::env_var("BORINGCACHE_DEFAULT_BRANCH").map(|v| normalize_ref(&v))
}

fn detect_ci_branch() -> Option<String> {
    for var in [
        "BORINGCACHE_GIT_BRANCH",
        "GITHUB_HEAD_REF",
        "GITHUB_REF_NAME",
        "CI_COMMIT_REF_NAME",
        "CI_COMMIT_BRANCH",
        "CIRCLE_BRANCH",
        "BITBUCKET_BRANCH",
    ] {
        if let Some(value) = crate::config::env_var(var) {
            return Some(normalize_ref(&value));
        }
    }
    None
}

fn detect_ci_sha() -> Option<String> {
    for var in [
        "BORINGCACHE_GIT_SHA",
        "GITHUB_SHA",
        "CI_COMMIT_SHA",
        "CIRCLE_SHA1",
        "BITBUCKET_COMMIT",
    ] {
        if let Ok(value) = env::var(var)
            && !value.trim().is_empty()
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn is_ci_env() -> bool {
    env::var("CI").is_ok()
        || env::var("GITHUB_ACTIONS").is_ok()
        || env::var("GITLAB_CI").is_ok()
        || env::var("CIRCLECI").is_ok()
        || env::var("BITBUCKET_BUILD_NUMBER").is_ok()
}

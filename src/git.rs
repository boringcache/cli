use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitContext {
    pub pr_number: Option<u32>,
    pub branch: Option<String>,
    pub default_branch: Option<String>,
    pub commit_sha: Option<String>,
}

impl GitContext {
    pub fn detect() -> Self {
        Self::detect_with_path(None)
    }

    pub fn detect_with_path(path_hint: Option<&str>) -> Self {
        if is_git_disabled_by_env() {
            return Self::default();
        }

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

    pub fn has_context(&self) -> bool {
        self.pr_number.is_some()
            || self.branch.is_some()
            || self.default_branch.is_some()
            || self.commit_sha.is_some()
    }

    pub fn branch_slug(&self) -> Option<String> {
        self.branch.as_ref().map(|branch| normalize_ref(branch))
    }

    pub fn default_branch_slug(&self) -> Option<String> {
        self.default_branch
            .as_ref()
            .map(|branch| normalize_ref(branch))
    }

    pub fn commit_slug(&self) -> Option<String> {
        self.commit_sha.as_ref().map(|sha| shorten_sha(sha))
    }
}

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

fn normalize_ref(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_was_dash = false;

    for ch in value.trim().chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else if matches!(ch, '-' | '_' | '.') {
            ch
        } else {
            '-'
        };

        if mapped == '-' {
            if last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }

        normalized.push(mapped);
        if normalized.len() >= 64 {
            break;
        }
    }

    let trimmed = normalized.trim_matches('-').trim_matches('.').to_string();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    }
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
        if candidate.is_file() {
            if let Ok(contents) = fs::read_to_string(&candidate) {
                if let Some(rest) = contents.strip_prefix("gitdir:") {
                    let gitdir = rest.trim();
                    let resolved = if Path::new(gitdir).is_absolute() {
                        PathBuf::from(gitdir)
                    } else {
                        current.join(gitdir)
                    };
                    return Some(resolved);
                }
            }
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
    if let Ok(contents) = fs::read_to_string(&origin_head) {
        if let Some(rest) = contents.trim().strip_prefix("ref:") {
            let reference = rest.trim();
            if let Some(branch_name) = reference.rsplit('/').next() {
                return Some(normalize_ref(branch_name));
            }
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
        if let Ok(value) = env::var(var) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
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

fn shorten_sha(sha: &str) -> String {
    sha.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _guard = ENV_LOCK.lock().unwrap();

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

        let original_default = std::env::var("BORINGCACHE_DEFAULT_BRANCH").ok();
        std::env::remove_var("BORINGCACHE_DEFAULT_BRANCH");

        let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
        if let Some(value) = original_default {
            std::env::set_var("BORINGCACHE_DEFAULT_BRANCH", value);
        }
        assert_eq!(ctx.branch.as_deref(), Some("main"));
        assert_eq!(ctx.default_branch.as_deref(), Some("main"));
    }

    #[test]
    fn detects_default_branch_from_origin_head() {
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

        let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
        assert_eq!(ctx.default_branch.as_deref(), Some("develop"));
    }

    #[test]
    fn missing_origin_head_returns_none() {
        let _guard = ENV_LOCK.lock().unwrap();

        let temp = tempfile::tempdir().unwrap();
        let git_dir = temp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/feature/x").unwrap();

        let original_default = std::env::var("BORINGCACHE_DEFAULT_BRANCH").ok();
        std::env::remove_var("BORINGCACHE_DEFAULT_BRANCH");
        let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
        if let Some(value) = original_default {
            std::env::set_var("BORINGCACHE_DEFAULT_BRANCH", value);
        }
        assert!(ctx.default_branch.is_none());
    }

    #[test]
    fn env_override_wins_for_default_branch() {
        let _guard = ENV_LOCK.lock().unwrap();

        let temp = tempfile::tempdir().unwrap();
        let git_dir = temp.path().join(".git");
        std::fs::create_dir_all(git_dir.join("refs/remotes/origin")).unwrap();
        std::fs::write(
            git_dir.join("refs/remotes/origin/HEAD"),
            "ref: refs/remotes/origin/main",
        )
        .unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main").unwrap();

        std::env::set_var("BORINGCACHE_DEFAULT_BRANCH", "develop");
        let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
        std::env::remove_var("BORINGCACHE_DEFAULT_BRANCH");

        assert_eq!(ctx.default_branch.as_deref(), Some("develop"));
    }

    #[test]
    fn ci_env_branch_used_when_branch_missing() {
        let _guard = ENV_LOCK.lock().unwrap();

        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("GITHUB_HEAD_REF", "feature/ci-branch");
        let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
        std::env::remove_var("GITHUB_HEAD_REF");

        assert_eq!(ctx.branch.as_deref(), Some("feature-ci-branch"));
    }

    #[test]
    fn ci_sha_used_when_no_branch() {
        let _guard = ENV_LOCK.lock().unwrap();

        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("CI", "true");
        std::env::set_var("GITHUB_SHA", "1234567890abcdef");
        std::env::remove_var("GITHUB_HEAD_REF");
        let ctx = GitContext::detect_with_path(Some(temp.path().to_str().unwrap()));
        std::env::remove_var("GITHUB_SHA");
        std::env::remove_var("CI");
        assert_eq!(ctx.commit_slug().as_deref(), Some("1234567890ab"));
    }
}

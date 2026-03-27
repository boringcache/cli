use crate::api::models::optimize::OptimizeChange;

#[derive(Debug, Clone)]
pub struct RuleResult {
    pub optimized_content: String,
    pub changes: Vec<OptimizeChange>,
    pub explanation: String,
}

pub fn apply(content: &str) -> Option<RuleResult> {
    if content.contains("boringcache ") || content.contains("boringcache/") {
        return None;
    }

    if !content.contains("cache:") {
        return None;
    }

    let cache_path = extract_first_cache_path(content)?;
    let entry = path_to_entry(&cache_path)?;

    let has_trailing_newline = content.ends_with('\n');
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();

    let removed_cache = remove_cache_blocks(&mut lines);
    if !removed_cache {
        return None;
    }

    ensure_before_script(&mut lines, &entry);
    ensure_after_script(&mut lines, &entry);

    let mut optimized = lines.join("\n");
    if has_trailing_newline {
        optimized.push('\n');
    }

    let changes = vec![
        OptimizeChange {
            description: "Removed GitLab cache: block in favor of boringcache CLI".to_string(),
            before_snippet: Some("cache:\n  key: ...\n  paths: ...".to_string()),
            after_snippet: Some(
                "before_script/after_script with boringcache restore/save".to_string(),
            ),
        },
        OptimizeChange {
            description: "Added boringcache restore/save commands to GitLab scripts".to_string(),
            before_snippet: None,
            after_snippet: Some(format!(
                "before_script:\n  - BORINGCACHE_API_TOKEN=$BORINGCACHE_API_TOKEN boringcache restore $CI_PROJECT_PATH \"{}\"\nafter_script:\n  - BORINGCACHE_API_TOKEN=$BORINGCACHE_API_TOKEN boringcache save $CI_PROJECT_PATH \"{}\"",
                entry, entry
            )),
        },
    ];

    Some(RuleResult {
        optimized_content: optimized,
        changes,
        explanation:
            "Deterministic pass migrated GitLab cache blocks to boringcache CLI restore/save hooks."
                .to_string(),
    })
}

fn remove_cache_blocks(lines: &mut Vec<String>) -> bool {
    let mut changed = false;
    let mut output = Vec::with_capacity(lines.len());
    let mut index = 0;

    while index < lines.len() {
        let line = &lines[index];
        let trimmed = line.trim_start();

        if trimmed == "cache:" {
            changed = true;
            let indent = leading_spaces(line);
            index += 1;

            while index < lines.len() {
                let next = &lines[index];
                if next.trim().is_empty() {
                    index += 1;
                    continue;
                }

                let next_indent = leading_spaces(next);
                if next_indent <= indent {
                    break;
                }
                index += 1;
            }

            continue;
        }

        output.push(line.clone());
        index += 1;
    }

    *lines = output;
    changed
}

fn ensure_before_script(lines: &mut Vec<String>, entry: &str) {
    if lines
        .iter()
        .any(|l| l.contains("boringcache restore $CI_PROJECT_PATH"))
    {
        return;
    }

    if let Some(index) = top_level_block_start(lines, "before_script:") {
        let block_end = top_level_block_end(lines, index + 1);
        lines.insert(
            block_end,
            format!(
                "  - BORINGCACHE_API_TOKEN=$BORINGCACHE_API_TOKEN boringcache restore $CI_PROJECT_PATH \"{}\"",
                entry
            ),
        );
        if !lines
            .iter()
            .any(|l| l.contains("install.boringcache.com/install.sh"))
        {
            lines.insert(
                block_end,
                "  - curl -sSL https://install.boringcache.com/install.sh | sh".to_string(),
            );
        }
        return;
    }

    let mut insert_at = 0;
    while insert_at < lines.len() && lines[insert_at].trim().is_empty() {
        insert_at += 1;
    }

    let mut block = vec![
        "before_script:".to_string(),
        "  - curl -sSL https://install.boringcache.com/install.sh | sh".to_string(),
        format!(
            "  - BORINGCACHE_API_TOKEN=$BORINGCACHE_API_TOKEN boringcache restore $CI_PROJECT_PATH \"{}\"",
            entry
        ),
    ];

    if insert_at < lines.len() {
        block.push(String::new());
    }

    for (offset, line) in block.into_iter().enumerate() {
        lines.insert(insert_at + offset, line);
    }
}

fn ensure_after_script(lines: &mut Vec<String>, entry: &str) {
    if lines
        .iter()
        .any(|l| l.contains("boringcache save $CI_PROJECT_PATH"))
    {
        return;
    }

    if let Some(index) = top_level_block_start(lines, "after_script:") {
        let block_end = top_level_block_end(lines, index + 1);
        lines.insert(
            block_end,
            format!(
                "  - BORINGCACHE_API_TOKEN=$BORINGCACHE_API_TOKEN boringcache save $CI_PROJECT_PATH \"{}\"",
                entry
            ),
        );
        return;
    }

    if !lines.is_empty() && !lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.push(String::new());
    }

    lines.push("after_script:".to_string());
    lines.push(format!(
        "  - BORINGCACHE_API_TOKEN=$BORINGCACHE_API_TOKEN boringcache save $CI_PROJECT_PATH \"{}\"",
        entry
    ));
}

fn top_level_block_start(lines: &[String], key: &str) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.trim_start() == key && leading_spaces(line) == 0)
}

fn top_level_block_end(lines: &[String], mut index: usize) -> usize {
    while index < lines.len() {
        let line = &lines[index];
        if line.trim().is_empty() {
            index += 1;
            continue;
        }

        if leading_spaces(line) == 0 {
            break;
        }

        index += 1;
    }

    index
}

fn extract_first_cache_path(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();
        if trimmed.starts_with("paths:") {
            let paths_indent = leading_spaces(line);
            index += 1;
            while index < lines.len() {
                let candidate = lines[index];
                if candidate.trim().is_empty() {
                    index += 1;
                    continue;
                }

                let candidate_indent = leading_spaces(candidate);
                if candidate_indent <= paths_indent {
                    break;
                }

                if let Some(rest) = candidate.trim_start().strip_prefix("- ") {
                    return Some(strip_quotes(rest.trim()).trim_end_matches('/').to_string());
                }

                index += 1;
            }
        }

        index += 1;
    }

    None
}

fn path_to_entry(path: &str) -> Option<String> {
    if path.contains("node_modules") {
        return Some("deps:node_modules".to_string());
    }
    if path.contains("vendor/bundle") {
        return Some("gems:vendor/bundle".to_string());
    }
    if path.contains(".cache/pip") {
        return Some("pip-cache:~/.cache/pip".to_string());
    }
    if path.contains(".gradle") {
        return Some("gradle-home:~/.gradle".to_string());
    }

    None
}

fn strip_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(value)
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_gitlab_cache_block() {
        let input = r#"build:
  image: node:20
  cache:
    key: ${CI_COMMIT_REF_SLUG}
    paths:
      - node_modules/
  script:
    - npm ci
    - npm test
"#;

        let result = apply(input).expect("expected rewrite");
        assert!(!result.optimized_content.contains("cache:"));
        assert!(
            result
                .optimized_content
                .contains("boringcache restore $CI_PROJECT_PATH \"deps:node_modules\"")
        );
        assert!(
            result
                .optimized_content
                .contains("boringcache save $CI_PROJECT_PATH \"deps:node_modules\"")
        );
    }

    #[test]
    fn returns_none_for_unknown_path() {
        let input = r#"build:
  cache:
    paths:
      - custom/cache/dir
"#;

        assert!(apply(input).is_none());
    }
}

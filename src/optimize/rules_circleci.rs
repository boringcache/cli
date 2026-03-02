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

    let has_restore = content.contains("restore_cache:");
    let has_save = content.contains("save_cache:");
    if !has_restore && !has_save {
        return None;
    }

    let cache_path = extract_first_cache_path(content)?;
    let entry = path_to_entry(&cache_path)?;

    let mut changes = Vec::new();
    let mut output_lines = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let has_trailing_newline = content.ends_with('\n');
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();

        if trimmed.starts_with("- restore_cache:") {
            let indent = leading_spaces(line);
            let block_end = find_block_end(&lines, index + 1, indent, "-");
            output_lines.extend(circle_install_lines(indent));
            output_lines.extend(circle_restore_lines(indent, &entry));
            changes.push(OptimizeChange {
                description: "Replaced restore_cache with boringcache restore command".to_string(),
                before_snippet: Some("- restore_cache:\n    keys: ...".to_string()),
                after_snippet: Some(format!(
                    "- run:\n    name: Restore BoringCache\n    command: BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache restore ${{CIRCLE_PROJECT_USERNAME}}/${{CIRCLE_PROJECT_REPONAME}} \"{}\"",
                    entry
                )),
            });
            index = block_end;
            continue;
        }

        if trimmed.starts_with("- save_cache:") {
            let indent = leading_spaces(line);
            let block_end = find_block_end(&lines, index + 1, indent, "-");
            output_lines.extend(circle_install_lines(indent));
            output_lines.extend(circle_save_lines(indent, &entry));
            changes.push(OptimizeChange {
                description: "Replaced save_cache with boringcache save command".to_string(),
                before_snippet: Some("- save_cache:\n    key: ...\n    paths: ...".to_string()),
                after_snippet: Some(format!(
                    "- run:\n    name: Save BoringCache\n    command: BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache save ${{CIRCLE_PROJECT_USERNAME}}/${{CIRCLE_PROJECT_REPONAME}} \"{}\"",
                    entry
                )),
            });
            index = block_end;
            continue;
        }

        output_lines.push(line.to_string());
        index += 1;
    }

    if changes.is_empty() {
        return None;
    }

    let mut optimized = output_lines.join("\n");
    if has_trailing_newline {
        optimized.push('\n');
    }

    Some(RuleResult {
        optimized_content: optimized,
        changes,
        explanation:
            "Deterministic pass migrated CircleCI restore_cache/save_cache to boringcache CLI commands."
                .to_string(),
    })
}

fn circle_install_lines(indent: usize) -> Vec<String> {
    let child_indent = indent + 2;
    vec![
        format!("{}- run:", " ".repeat(indent)),
        format!("{}name: Install BoringCache", " ".repeat(child_indent)),
        format!(
            "{}command: curl -sSL https://install.boringcache.com/install.sh | sh",
            " ".repeat(child_indent)
        ),
    ]
}

fn circle_restore_lines(indent: usize, entry: &str) -> Vec<String> {
    let child_indent = indent + 2;
    vec![
        format!("{}- run:", " ".repeat(indent)),
        format!("{}name: Restore BoringCache", " ".repeat(child_indent)),
        format!(
            "{}command: BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache restore ${{CIRCLE_PROJECT_USERNAME}}/${{CIRCLE_PROJECT_REPONAME}} \"{}\"",
            " ".repeat(child_indent),
            entry
        ),
    ]
}

fn circle_save_lines(indent: usize, entry: &str) -> Vec<String> {
    let child_indent = indent + 2;
    vec![
        format!("{}- run:", " ".repeat(indent)),
        format!("{}name: Save BoringCache", " ".repeat(child_indent)),
        format!(
            "{}command: BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache save ${{CIRCLE_PROJECT_USERNAME}}/${{CIRCLE_PROJECT_REPONAME}} \"{}\"",
            " ".repeat(child_indent),
            entry
        ),
    ]
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

                let candidate_trimmed = candidate.trim_start();
                if let Some(rest) = candidate_trimmed.strip_prefix("- ") {
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

fn find_block_end(lines: &[&str], mut idx: usize, indent: usize, list_prefix: &str) -> usize {
    while idx < lines.len() {
        let line = lines[idx];
        if line.trim().is_empty() {
            idx += 1;
            continue;
        }

        let current_indent = leading_spaces(line);
        let trimmed = line.trim_start();
        if current_indent <= indent && trimmed.starts_with(list_prefix) {
            break;
        }
        if current_indent < indent {
            break;
        }

        idx += 1;
    }

    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_restore_and_save_cache_steps() {
        let input = r#"version: 2.1
jobs:
  build:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - restore_cache:
          keys:
            - deps-{{ checksum \"package-lock.json\" }}
      - run: npm ci
      - save_cache:
          key: deps-{{ checksum \"package-lock.json\" }}
          paths:
            - node_modules
"#;

        let result = apply(input).expect("expected rewrite");
        assert!(result
            .optimized_content
            .contains("boringcache restore ${CIRCLE_PROJECT_USERNAME}/${CIRCLE_PROJECT_REPONAME} \"deps:node_modules\""));
        assert!(result
            .optimized_content
            .contains("boringcache save ${CIRCLE_PROJECT_USERNAME}/${CIRCLE_PROJECT_REPONAME} \"deps:node_modules\""));
        assert!(!result.optimized_content.contains("restore_cache:"));
        assert!(!result.optimized_content.contains("save_cache:"));
    }

    #[test]
    fn returns_none_for_unknown_path() {
        let input = r#"steps:
  - save_cache:
      key: deps
      paths:
        - custom/cache/dir
"#;

        assert!(apply(input).is_none());
    }
}

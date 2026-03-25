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

    if !content.contains("cache#") {
        return None;
    }

    let cache_path = extract_first_cache_path(content)?;
    let entry = path_to_entry(&cache_path)?;

    let has_trailing_newline = content.ends_with('\n');
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();

    let removed_plugin = remove_cache_plugin_block(&mut lines);
    if !removed_plugin {
        return None;
    }

    let injected_commands = inject_commands(&mut lines, &entry);
    if !injected_commands {
        return None;
    }

    let mut optimized = lines.join("\n");
    if has_trailing_newline {
        optimized.push('\n');
    }

    let changes = vec![
        OptimizeChange {
            description: "Removed Buildkite cache plugin block".to_string(),
            before_snippet: Some("plugins:\n  - cache#...".to_string()),
            after_snippet: Some("commands with boringcache restore/save".to_string()),
        },
        OptimizeChange {
            description: "Added boringcache restore/save commands to Buildkite commands"
                .to_string(),
            before_snippet: None,
            after_snippet: Some(format!(
                "- BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache restore ${{BUILDKITE_ORGANIZATION_SLUG}}/${{BUILDKITE_PIPELINE_SLUG}} \"{}\"\n- BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache save ${{BUILDKITE_ORGANIZATION_SLUG}}/${{BUILDKITE_PIPELINE_SLUG}} \"{}\"",
                entry, entry
            )),
        },
    ];

    Some(RuleResult {
        optimized_content: optimized,
        changes,
        explanation:
            "Deterministic pass migrated Buildkite cache plugin usage to boringcache CLI commands."
                .to_string(),
    })
}

fn remove_cache_plugin_block(lines: &mut Vec<String>) -> bool {
    let mut changed = false;
    let mut output = Vec::with_capacity(lines.len());
    let mut index = 0;

    while index < lines.len() {
        let line = &lines[index];
        let trimmed = line.trim_start();

        if trimmed.starts_with("- cache#") {
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
                let next_trimmed = next.trim_start();
                if next_indent <= indent && next_trimmed.starts_with("-") {
                    break;
                }
                if next_indent < indent {
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

fn inject_commands(lines: &mut Vec<String>, entry: &str) -> bool {
    let Some(commands_index) = lines
        .iter()
        .position(|line| line.trim_start() == "commands:")
    else {
        return false;
    };

    let commands_indent = leading_spaces(&lines[commands_index]);
    let command_item_indent = commands_indent + 2;
    let command_item_prefix = format!("{}- ", " ".repeat(command_item_indent));

    let mut block_end = commands_index + 1;
    while block_end < lines.len() {
        let current = &lines[block_end];
        if current.trim().is_empty() {
            block_end += 1;
            continue;
        }

        let current_indent = leading_spaces(current);
        if current_indent <= commands_indent {
            break;
        }

        block_end += 1;
    }

    let prepend = vec![
        format!(
            "{}curl -sSL https://install.boringcache.com/install.sh | sh",
            command_item_prefix
        ),
        format!(
            "{}BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache restore ${{BUILDKITE_ORGANIZATION_SLUG}}/${{BUILDKITE_PIPELINE_SLUG}} \"{}\"",
            command_item_prefix, entry
        ),
    ];

    for (offset, line) in prepend.into_iter().enumerate() {
        lines.insert(commands_index + 1 + offset, line);
    }

    let adjusted_block_end = block_end + 2;
    lines.insert(
        adjusted_block_end,
        format!(
            "{}BORINGCACHE_API_TOKEN=${{BORINGCACHE_API_TOKEN}} boringcache save ${{BUILDKITE_ORGANIZATION_SLUG}}/${{BUILDKITE_PIPELINE_SLUG}} \"{}\"",
            command_item_prefix, entry
        ),
    );

    true
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
    fn rewrites_buildkite_cache_plugin() {
        let input = r#"steps:
  - label: ":nodejs: Build & Test"
    plugins:
      - cache#v1.0.0:
          paths:
            - node_modules
    commands:
      - npm ci
      - npm test
"#;

        let result = apply(input).expect("expected rewrite");
        assert!(!result.optimized_content.contains("cache#v1.0.0"));
        assert!(result
            .optimized_content
            .contains("boringcache restore ${BUILDKITE_ORGANIZATION_SLUG}/${BUILDKITE_PIPELINE_SLUG} \"deps:node_modules\""));
        assert!(result
            .optimized_content
            .contains("boringcache save ${BUILDKITE_ORGANIZATION_SLUG}/${BUILDKITE_PIPELINE_SLUG} \"deps:node_modules\""));
    }

    #[test]
    fn returns_none_for_unknown_path() {
        let input = r#"steps:
  - label: test
    plugins:
      - cache#v1.0.0:
          paths:
            - custom/cache/dir
    commands:
      - make test
"#;

        assert!(apply(input).is_none());
    }
}

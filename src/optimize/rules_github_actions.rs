use crate::api::models::optimize::OptimizeChange;

#[derive(Debug, Clone)]
pub struct RuleResult {
    pub optimized_content: String,
    pub changes: Vec<OptimizeChange>,
    pub explanation: String,
}

pub fn apply(content: &str) -> Option<RuleResult> {
    if contains_split_actions_cache_steps(content) {
        return None;
    }

    let (rewritten, mut changes, replaced) = rewrite_actions_cache_usages(content);
    if !replaced {
        return None;
    }

    let (optimized_content, token_added) = ensure_token_on_boringcache_steps(&rewritten);
    if token_added {
        changes.push(OptimizeChange {
            description: "Added BORINGCACHE_API_TOKEN env to BoringCache action steps".to_string(),
            before_snippet: None,
            after_snippet: Some(
                "env:\n  BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_API_TOKEN }}".to_string(),
            ),
        });
    }

    Some(RuleResult {
        optimized_content,
        changes,
        explanation: "Deterministic pass migrated actions/cache usage to boringcache/one."
            .to_string(),
    })
}

fn rewrite_actions_cache_usages(content: &str) -> (String, Vec<OptimizeChange>, bool) {
    let mut changed = false;
    let mut changes = Vec::new();
    let mut out = String::with_capacity(content.len() + 64);

    for line in content.split_inclusive('\n') {
        let mut rewritten_line = line.to_string();

        if let Some(new_line) = replace_action_reference(
            &rewritten_line,
            "uses: actions/cache@",
            "uses: boringcache/one@v1",
        ) {
            rewritten_line = new_line;
            changed = true;
            changes.push(OptimizeChange {
                description: "Replaced actions/cache with boringcache/one@v1".to_string(),
                before_snippet: Some("uses: actions/cache@...".to_string()),
                after_snippet: Some("uses: boringcache/one@v1".to_string()),
            });
        } else if let Some(new_line) = replace_action_reference(
            &rewritten_line,
            "uses: actions/cache",
            "uses: boringcache/one@v1",
        ) {
            rewritten_line = new_line;
            changed = true;
            changes.push(OptimizeChange {
                description: "Replaced actions/cache with boringcache/one@v1".to_string(),
                before_snippet: Some("uses: actions/cache".to_string()),
                after_snippet: Some("uses: boringcache/one@v1".to_string()),
            });
        }

        out.push_str(&rewritten_line);
    }

    (out, changes, changed)
}

fn contains_split_actions_cache_steps(content: &str) -> bool {
    content.contains("uses: actions/cache/restore") || content.contains("uses: actions/cache/save")
}

fn replace_action_reference(line: &str, old_marker: &str, replacement: &str) -> Option<String> {
    let start = line.find(old_marker)?;
    let suffix = &line[start + old_marker.len()..];

    let mut consumed = 0;
    for (i, ch) in suffix.char_indices() {
        if ch.is_whitespace() || ch == '#' {
            break;
        }
        consumed = i + ch.len_utf8();
    }

    let end = start + old_marker.len() + consumed;
    let mut rewritten = String::with_capacity(line.len() + replacement.len());
    rewritten.push_str(&line[..start]);
    rewritten.push_str(replacement);
    rewritten.push_str(&line[end..]);
    Some(rewritten)
}

fn ensure_token_on_boringcache_steps(content: &str) -> (String, bool) {
    let has_trailing_newline = content.ends_with('\n');
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
    let mut inserted_token = false;

    let mut i = 0;
    while i < lines.len() {
        if !line_is_boringcache_step(&lines[i]) {
            i += 1;
            continue;
        }

        let step_indent = count_leading_spaces(&lines[i]);
        let child_indent = step_indent + 2;
        let step_end = find_step_end(&lines, i + 1, step_indent);
        let env_start = find_env_block_start(&lines, i + 1, step_end, child_indent);

        if let Some(env_start) = env_start {
            let env_end = find_env_block_end(&lines, env_start + 1, child_indent);
            let has_token = lines[env_start + 1..env_end]
                .iter()
                .any(|line| line.trim_start().starts_with("BORINGCACHE_API_TOKEN:"));

            if !has_token {
                lines.insert(
                    env_end,
                    format!(
                        "{}BORINGCACHE_API_TOKEN: ${{{{ secrets.BORINGCACHE_API_TOKEN }}}}",
                        " ".repeat(child_indent + 2)
                    ),
                );
                inserted_token = true;
                i += 1;
            }
        } else {
            lines.insert(i + 1, format!("{}env:", " ".repeat(child_indent)));
            lines.insert(
                i + 2,
                format!(
                    "{}BORINGCACHE_API_TOKEN: ${{{{ secrets.BORINGCACHE_API_TOKEN }}}}",
                    " ".repeat(child_indent + 2)
                ),
            );
            inserted_token = true;
            i += 2;
        }

        i += 1;
    }

    let mut rebuilt = lines.join("\n");
    if has_trailing_newline {
        rebuilt.push('\n');
    }
    (rebuilt, inserted_token)
}

fn line_is_boringcache_step(line: &str) -> bool {
    line.trim_start().starts_with("- uses: boringcache/")
}

fn count_leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn find_step_end(lines: &[String], mut index: usize, step_indent: usize) -> usize {
    while index < lines.len() {
        let line = &lines[index];
        if line.trim().is_empty() {
            index += 1;
            continue;
        }

        let indent = count_leading_spaces(line);
        let trimmed = line.trim_start();
        if (indent <= step_indent && trimmed.starts_with("- ")) || indent < step_indent {
            break;
        }
        index += 1;
    }

    index
}

fn find_env_block_start(
    lines: &[String],
    start: usize,
    end: usize,
    child_indent: usize,
) -> Option<usize> {
    for (idx, line) in lines.iter().enumerate().skip(start).take(end - start) {
        if line.trim().is_empty() {
            continue;
        }

        let indent = count_leading_spaces(line);
        if indent == child_indent && line.trim_start() == "env:" {
            return Some(idx);
        }
    }

    None
}

fn find_env_block_end(lines: &[String], mut index: usize, child_indent: usize) -> usize {
    while index < lines.len() {
        let line = &lines[index];
        if line.trim().is_empty() {
            index += 1;
            continue;
        }

        let indent = count_leading_spaces(line);
        if indent <= child_indent {
            break;
        }
        index += 1;
    }

    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transforms_actions_cache_and_injects_token() {
        let input = r#"name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: deps-${{ hashFiles('package-lock.json') }}
      - run: npm ci
"#;

        let result = apply(input).expect("expected deterministic rewrite");
        assert!(result
            .optimized_content
            .contains("uses: boringcache/one@v1"));
        assert!(result
            .optimized_content
            .contains("BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_API_TOKEN }}"));
        assert!(!result.optimized_content.contains("uses: actions/cache"));
        assert!(!result.changes.is_empty());
    }

    #[test]
    fn returns_none_for_restore_and_save_variants() {
        let input = r#"jobs:
  test:
    steps:
      - uses: actions/cache/restore@v4
      - run: npm ci
      - uses: actions/cache/save@v4
"#;

        assert!(apply(input).is_none());
    }

    #[test]
    fn returns_none_when_no_supported_pattern() {
        let input = "name: CI\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n";
        assert!(apply(input).is_none());
    }

    #[test]
    fn does_not_duplicate_existing_token() {
        let input = r#"jobs:
  test:
    steps:
      - uses: actions/cache@v4
        env:
          BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_API_TOKEN }}
"#;

        let result = apply(input).expect("expected rewrite");
        let token_count = result
            .optimized_content
            .matches("BORINGCACHE_API_TOKEN:")
            .count();
        assert_eq!(token_count, 1);
    }
}

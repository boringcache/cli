use crate::api::models::optimize::{OptimizeChange, OptimizeFileResult};

use super::{
    rules_buildkite, rules_circleci, rules_dockerfile, rules_github_actions, rules_gitlab_ci,
    CiType,
};

#[derive(Debug, Clone)]
pub enum TransformResult {
    Optimized {
        optimized_content: String,
        changes: Vec<OptimizeChange>,
        explanation: String,
    },
    NoChanges {
        reason: String,
    },
    Unsupported {
        reason: String,
    },
}

pub fn deterministic_optimize(ci_type: CiType, content: &str) -> TransformResult {
    match ci_type {
        CiType::GitHubActions => {
            if let Some(result) = rules_github_actions::apply(content) {
                TransformResult::Optimized {
                    optimized_content: result.optimized_content,
                    changes: result.changes,
                    explanation: result.explanation,
                }
            } else {
                TransformResult::NoChanges {
                    reason: "No supported deterministic GitHub Actions cache pattern found"
                        .to_string(),
                }
            }
        }
        CiType::Dockerfile => {
            if let Some(result) = rules_dockerfile::apply(content) {
                TransformResult::Optimized {
                    optimized_content: result.optimized_content,
                    changes: result.changes,
                    explanation: result.explanation,
                }
            } else {
                TransformResult::Unsupported {
                    reason: "Deterministic Dockerfile rules are not available for this file yet"
                        .to_string(),
                }
            }
        }
        CiType::CircleCi => {
            if let Some(result) = rules_circleci::apply(content) {
                TransformResult::Optimized {
                    optimized_content: result.optimized_content,
                    changes: result.changes,
                    explanation: result.explanation,
                }
            } else {
                TransformResult::NoChanges {
                    reason: "No supported deterministic CircleCI cache pattern found".to_string(),
                }
            }
        }
        CiType::GitLabCi => {
            if let Some(result) = rules_gitlab_ci::apply(content) {
                TransformResult::Optimized {
                    optimized_content: result.optimized_content,
                    changes: result.changes,
                    explanation: result.explanation,
                }
            } else {
                TransformResult::NoChanges {
                    reason: "No supported deterministic GitLab CI cache pattern found".to_string(),
                }
            }
        }
        CiType::Buildkite => {
            if let Some(result) = rules_buildkite::apply(content) {
                TransformResult::Optimized {
                    optimized_content: result.optimized_content,
                    changes: result.changes,
                    explanation: result.explanation,
                }
            } else {
                TransformResult::NoChanges {
                    reason: "No supported deterministic Buildkite cache pattern found".to_string(),
                }
            }
        }
        _ => TransformResult::Unsupported {
            reason: format!(
                "Deterministic rules are not available for {}",
                ci_type.label()
            ),
        },
    }
}

pub fn validate_output(original: &str, optimized: &str) -> std::result::Result<(), String> {
    if optimized.trim().is_empty() {
        return Err("optimized content is empty".to_string());
    }

    let uses_boringcache = optimized.contains("boringcache/")
        || optimized.contains("boringcache save")
        || optimized.contains("boringcache restore");

    if uses_boringcache && !optimized.contains("BORINGCACHE_API_TOKEN") {
        return Err("output uses BoringCache but is missing BORINGCACHE_API_TOKEN".to_string());
    }

    if contains_secret_exfiltration(optimized) {
        return Err("output contains insecure secret handling patterns".to_string());
    }

    if uses_boringcache {
        let insecure_token_line = optimized
            .lines()
            .find(|line| line.contains("BORINGCACHE_API_TOKEN") && !token_reference_is_safe(line));
        if insecure_token_line.is_some() {
            return Err("output contains insecure BORINGCACHE_API_TOKEN reference".to_string());
        }
    }

    let original_len = original.len();
    let optimized_len = optimized.len();
    if original_len > 100 && optimized_len < original_len / 2 {
        return Err(format!(
            "output appears truncated ({} chars vs {} original)",
            optimized_len, original_len
        ));
    }

    Ok(())
}

fn contains_secret_exfiltration(content: &str) -> bool {
    let lowered = content.to_lowercase();
    lowered.contains("echo $boringcache_api_token")
        || lowered.contains("printenv boringcache_api_token")
        || lowered.contains("env | grep boringcache_api_token")
}

fn token_reference_is_safe(line: &str) -> bool {
    let trimmed = line.trim();

    if trimmed.starts_with('#') {
        return true;
    }

    if trimmed.contains("BORINGCACHE_API_TOKEN:") {
        return trimmed.contains("${{ secrets.")
            || trimmed.contains("$BORINGCACHE_API_TOKEN")
            || trimmed.contains("${BORINGCACHE_API_TOKEN}")
            || trimmed.contains("$(cat /run/secrets/boringcache_token)");
    }

    if let Some(index) = trimmed.find("BORINGCACHE_API_TOKEN=") {
        let rhs = trimmed[index + "BORINGCACHE_API_TOKEN=".len()..].trim();
        return rhs.starts_with('$')
            || rhs.starts_with("${")
            || rhs.starts_with("\"$")
            || rhs.starts_with("'$")
            || rhs.starts_with("$(cat /run/secrets/boringcache_token)");
    }

    true
}

pub fn preserve_trailing_newline(original: &str, optimized: &str) -> String {
    let original_ends_with_newline = original.ends_with('\n');
    let optimized_ends_with_newline = optimized.ends_with('\n');

    match (original_ends_with_newline, optimized_ends_with_newline) {
        (true, false) => format!("{}\n", optimized),
        (false, true) => optimized.trim_end_matches('\n').to_string(),
        _ => optimized.to_string(),
    }
}

pub fn no_changes_result(path: String, ci_type: CiType, reason: String) -> OptimizeFileResult {
    OptimizeFileResult {
        path,
        status: "no_changes".to_string(),
        detected_type: ci_type.api_key().map(str::to_string),
        optimized_content: None,
        changes: vec![],
        explanation: Some(reason),
        error: None,
    }
}

pub fn error_result(path: String, ci_type: CiType, error: String) -> OptimizeFileResult {
    OptimizeFileResult {
        path,
        status: "error".to_string(),
        detected_type: ci_type.api_key().map(str::to_string),
        optimized_content: None,
        changes: vec![],
        explanation: None,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_output_empty() {
        assert!(validate_output("original", "").is_err());
        assert!(validate_output("original", "  \n  ").is_err());
    }

    #[test]
    fn validate_output_missing_token() {
        let optimized = "- uses: boringcache/action@v1\n  with:\n    workspace: test";
        assert!(validate_output("original", optimized).is_err());
    }

    #[test]
    fn validate_output_with_token() {
        let optimized =
            "- uses: boringcache/action@v1\n  env:\n    BORINGCACHE_API_TOKEN: ${{ secrets.BORINGCACHE_API_TOKEN }}";
        assert!(validate_output("original content here", optimized).is_ok());
    }

    #[test]
    fn validate_output_truncated() {
        let original = "x".repeat(200);
        let optimized = "short";
        assert!(validate_output(&original, optimized).is_err());
    }

    #[test]
    fn validate_output_no_boringcache_no_token_ok() {
        assert!(validate_output("original", "some optimized content without boringcache").is_ok());
    }

    #[test]
    fn validate_output_rejects_plaintext_token_assignment() {
        let optimized =
            "- uses: boringcache/action@v1\n  env:\n    BORINGCACHE_API_TOKEN: abc123plaintext";
        assert!(validate_output("orig", optimized).is_err());
    }

    #[test]
    fn validate_output_rejects_secret_exfiltration_patterns() {
        let optimized = "run: echo $BORINGCACHE_API_TOKEN";
        assert!(validate_output("orig", optimized).is_err());
    }

    #[test]
    fn preserve_trailing_newline_behavior() {
        assert_eq!(
            preserve_trailing_newline("original\n", "optimized"),
            "optimized\n"
        );
        assert_eq!(
            preserve_trailing_newline("original", "optimized\n"),
            "optimized"
        );
        assert_eq!(
            preserve_trailing_newline("original\n", "optimized\n"),
            "optimized\n"
        );
        assert_eq!(
            preserve_trailing_newline("original", "optimized"),
            "optimized"
        );
    }

    #[test]
    fn deterministic_circleci_supported_pattern() {
        let input = r#"version: 2.1
jobs:
  build:
    steps:
      - restore_cache:
          keys:
            - deps-{{ checksum "package-lock.json" }}
      - save_cache:
          key: deps-{{ checksum "package-lock.json" }}
          paths:
            - node_modules
"#;

        match deterministic_optimize(CiType::CircleCi, input) {
            TransformResult::Optimized {
                optimized_content, ..
            } => {
                assert!(optimized_content.contains("boringcache restore"));
                assert!(optimized_content.contains("boringcache save"));
            }
            other => panic!("expected optimized result, got {other:?}"),
        }
    }
}

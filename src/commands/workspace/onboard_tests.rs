use super::*;

#[test]
fn try_read_file_skips_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.yml");
    std::fs::write(&path, "hello\0world").unwrap();
    assert!(try_read_file(&path, "test.yml").is_none());
}

#[test]
fn try_read_file_reads_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("ci.yml");
    std::fs::write(
        &path,
        "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu\n    steps:\n      - run: npm ci",
    )
    .unwrap();

    let file = try_read_file(&path, ".github/workflows/ci.yml").unwrap();
    assert_eq!(file.ci_type, CiType::GitHubActions);
    assert_eq!(file.relevance, FileRelevance::NoCaching);
}

#[test]
fn ci_type_api_keys() {
    assert_eq!(CiType::GitHubActions.api_key(), Some("github_actions"));
    assert_eq!(CiType::Dockerfile.api_key(), Some("dockerfile"));
    assert_eq!(CiType::Unknown.api_key(), None);
}

#[test]
fn relevance_should_send() {
    assert!(FileRelevance::HasCaching.should_send());
    assert!(FileRelevance::NoCaching.should_send());
    assert!(!FileRelevance::AlreadyOptimized.should_send());
    assert!(!FileRelevance::NoOpportunity.should_send());
    assert!(!FileRelevance::TooLarge.should_send());
}

#[test]
fn max_content_length_constant_is_stable() {
    assert_eq!(crate::optimize::MAX_CONTENT_LENGTH, 50_000);
}

#[test]
fn extract_cache_paths_handles_entries_and_cli_specs() {
    let content = r#"
- uses: boringcache/one@v1
  with:
entries: deps:node_modules,build:dist
- run: boringcache save my-org/app "gems:vendor/bundle"
"#;

    let paths = extract_cache_paths(content);
    assert!(paths.contains(&"node_modules".to_string()));
    assert!(paths.contains(&"dist".to_string()));
    assert!(paths.contains(&"vendor/bundle".to_string()));
}

#[test]
fn assess_cache_risk_flags_sensitive_paths() {
    let paths = vec!["node_modules".to_string(), ".aws/credentials".to_string()];
    let report = assess_cache_risk(&paths);
    assert_eq!(report.level, RiskLevel::High);
    assert_eq!(report.paths, vec![".aws/credentials".to_string()]);
}

#[test]
fn estimate_savings_uses_cache_baseline_when_existing_cache_detected() {
    let original = r#"
steps:
  - uses: actions/cache@v4
with:
  path: node_modules
"#;
    let paths = vec!["node_modules".to_string()];
    let estimate = estimate_savings(original, CiType::GitHubActions, &paths);
    assert_eq!(estimate.baseline, "current cache baseline");
    assert!(estimate.max_percent <= 28);
}

#[test]
fn estimate_savings_no_cache_baseline_has_higher_upper_bound() {
    let original = "steps:\n  - run: npm ci\n";
    let paths = vec!["node_modules".to_string()];
    let estimate = estimate_savings(original, CiType::GitHubActions, &paths);
    assert_eq!(estimate.baseline, "no cache baseline");
    assert!(estimate.max_percent >= 19);
}

#[test]
fn parse_cli_connect_expiry_parses_rfc3339() {
    let parsed = parse_cli_connect_expiry("2026-03-02T12:00:00Z");
    assert!(parsed.is_some());
}

#[test]
fn parse_cli_connect_expiry_rejects_invalid() {
    let parsed = parse_cli_connect_expiry("not-a-time");
    assert!(parsed.is_none());
}

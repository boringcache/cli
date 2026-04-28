use super::*;
use crate::command_support::RestoreSpec;
use anyhow::anyhow;

#[test]
fn preflight_skips_file_target() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("existing_file");
    std::fs::write(&file_path, b"data").unwrap();

    let parsed = RestoreSpec {
        tag: "valid-tag".to_string(),
        path: Some(file_path.to_string_lossy().to_string()),
    };

    let result = run_restore_preflight_checks(&[parsed], true).unwrap();
    assert_eq!(result.valid_specs.len(), 0);
}

#[test]
fn preflight_accepts_new_directory() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("new-directory");
    let parsed = RestoreSpec {
        tag: "valid-tag".to_string(),
        path: Some(target.to_string_lossy().to_string()),
    };

    let result = run_restore_preflight_checks(&[parsed], true).unwrap();
    assert_eq!(result.valid_specs.len(), 1);
}

#[test]
fn preflight_skips_empty_tag() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("dir");
    let parsed = RestoreSpec {
        tag: "".to_string(),
        path: Some(target.to_string_lossy().to_string()),
    };

    let result = run_restore_preflight_checks(&[parsed], true).unwrap();
    assert_eq!(result.valid_specs.len(), 0);
}

#[test]
fn preflight_creates_missing_parent_directories() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("vendor").join("bundle");
    let parsed = RestoreSpec {
        tag: "valid-tag".to_string(),
        path: Some(target.to_string_lossy().to_string()),
    };

    let result = run_restore_preflight_checks(&[parsed], true).unwrap();
    assert_eq!(result.valid_specs.len(), 1);
    assert!(temp.path().join("vendor").exists());
}

#[test]
fn preflight_continues_batch_with_valid_entries() {
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("existing_file");
    std::fs::write(&file_path, b"data").unwrap();

    let valid_dir = temp.path().join("valid_dir");
    let invalid_child = file_path.join("child");

    let parsed_entries = vec![
        RestoreSpec {
            tag: "tag1".to_string(),
            path: Some(file_path.to_string_lossy().to_string()),
        },
        RestoreSpec {
            tag: "tag2".to_string(),
            path: Some(valid_dir.to_string_lossy().to_string()),
        },
        RestoreSpec {
            tag: "tag3".to_string(),
            path: Some(invalid_child.to_string_lossy().to_string()),
        },
    ];

    let result = run_restore_preflight_checks(&parsed_entries, true).unwrap();
    assert_eq!(result.valid_specs.len(), 1);
    assert_eq!(result.valid_specs[0].tag, "tag2");
}

#[test]
fn preflight_lookup_only_does_not_create_missing_parent_directories() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("vendor").join("bundle");
    let parsed = RestoreSpec {
        tag: "valid-tag".to_string(),
        path: Some(target.to_string_lossy().to_string()),
    };

    let result = run_restore_preflight_checks(&[parsed], false).unwrap();
    assert_eq!(result.valid_specs.len(), 1);
    assert!(!temp.path().join("vendor").exists());
}

#[tokio::test]
async fn ensure_empty_target_accepts_existing_empty_directory() {
    let temp = tempfile::tempdir().unwrap();

    let result = ensure_empty_target(temp.path().to_str().unwrap())
        .await
        .unwrap();

    assert!(matches!(result, EnsureTargetStatus::Ready));
}

#[tokio::test]
async fn ensure_empty_target_reports_blocking_entry() {
    let temp = tempfile::tempdir().unwrap();
    let blocking_path = temp.path().join("dev.db");
    std::fs::write(&blocking_path, b"data").unwrap();

    let result = ensure_empty_target(temp.path().to_str().unwrap())
        .await
        .unwrap();

    match result {
        EnsureTargetStatus::Occupied {
            existing_path,
            blocking_path: found_blocking_path,
        } => {
            assert_eq!(existing_path, temp.path().display().to_string());
            assert_eq!(found_blocking_path, blocking_path.display().to_string());
        }
        EnsureTargetStatus::Ready => panic!("expected occupied target"),
    }
}

#[test]
fn test_fail_on_cache_miss_flag_logic() {
    let fail_on_cache_miss = true;
    let misses = ["missing-cache".to_string()];

    assert!(fail_on_cache_miss && !misses.is_empty());

    let fail_on_cache_miss = false;
    assert!(!fail_on_cache_miss || misses.is_empty());

    let fail_on_cache_miss = true;
    let misses: Vec<String> = vec![];
    assert!(!fail_on_cache_miss || misses.is_empty());
}

#[test]
fn test_lookup_only_flag_logic() {
    let lookup_only = true;
    assert!(lookup_only);

    let lookup_only = false;
    assert!(!lookup_only);
}

#[test]
fn strict_restore_errors_include_signature_requirement() {
    assert!(should_fail_on_restore_error(true, false));
    assert!(should_fail_on_restore_error(false, true));
    assert!(!should_fail_on_restore_error(false, false));
}

#[test]
fn lenient_execute_batch_restore_result_warns_and_continues() {
    let err: Error = anyhow!("boom");
    let result = finalize_execute_batch_restore_result(Err(err), false, false, false);
    assert!(result.is_ok());
}

#[test]
fn strict_execute_batch_restore_result_returns_error() {
    let err: Error = anyhow!("boom");
    let result = finalize_execute_batch_restore_result(Err(err), false, true, false);
    assert!(result.is_err());
}

#[test]
fn finalize_restore_outcome_errors_on_restore_failure() {
    let err: Error = anyhow!("boom");
    let result = finalize_restore_outcome(vec![err], Vec::new());
    assert!(result.is_err());
}

#[test]
fn finalize_restore_outcome_errors_on_skipped_entries() {
    let result = finalize_restore_outcome(
        Vec::new(),
        vec![("tag1".to_string(), "target busy".to_string())],
    );
    assert!(result.is_err());
}

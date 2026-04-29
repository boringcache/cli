use super::*;

#[test]
fn oci_success_rollup_without_degraded_header_is_hit() {
    let response = (StatusCode::CREATED, Body::empty()).into_response();
    let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
    assert_eq!(
        result,
        crate::serve::cache_registry::cache_ops::OpResult::Hit
    );
    assert!(!degraded);
}

#[test]
fn oci_success_rollup_with_degraded_header_is_error() {
    let response = (
        StatusCode::CREATED,
        [(OCI_DEGRADED_HEADER, "1")],
        Body::empty(),
    )
        .into_response();
    let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
    assert_eq!(
        result,
        crate::serve::cache_registry::cache_ops::OpResult::Error
    );
    assert!(degraded);
}

#[test]
fn oci_success_rollup_with_non_success_response_is_error() {
    let response = (StatusCode::RANGE_NOT_SATISFIABLE, Body::empty()).into_response();
    let (result, degraded) = oci_success_rollup_result(&response, OCI_DEGRADED_HEADER);
    assert_eq!(
        result,
        crate::serve::cache_registry::cache_ops::OpResult::Error
    );
    assert!(!degraded);
}

#[tokio::test]
async fn proxy_status_includes_live_session_summary() {
    let state = test_state();

    let response = proxy_status(State(state)).await.into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("proxy status body");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("proxy status should be JSON");

    let summary = &json["session_summary"];
    assert_eq!(summary["schema"], "cache-session-v2");
    assert_eq!(summary["mode"], "cache-registry");
    assert_eq!(summary["adapter"], "runtime");
    assert_eq!(summary["workspace"], "boringcache/benchmarks");
    assert_eq!(summary["proxy"]["hydration_policy"], "metadata-only");
    assert_eq!(summary["proxy"]["blob_prefetch_max_concurrency"], 2);
    assert!(summary["backend_api"].is_object());
    assert!(summary["rails"].is_object());
    assert!(summary["startup_prefetch"].is_object());
    assert!(summary["lifecycle"].is_object());
    assert_eq!(summary["buildkit"]["run_classification"], "not_applicable");
    assert!(summary["classification"]["issue_candidates"].is_array());
    assert!(summary["duration_ms"].as_u64().is_some());
}

#[tokio::test]
async fn oci_dispatch_records_blob_miss_rollup_and_missed_key() {
    let state = test_state();
    let result = oci_dispatch(
        Method::GET,
        State(state.clone()),
        Path(
            "cache/blobs/sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
        ),
        Query(HashMap::new()),
        HeaderMap::new(),
        Body::empty(),
    )
    .await;

    let error = result.expect_err("blob should be missing");
    assert_eq!(error.status(), StatusCode::NOT_FOUND);

    let (rollups, missed, sessions) = state.cache_ops.drain();
    assert!(sessions.is_empty());
    let miss_rollup = rollups
        .iter()
        .find(|record| record.tool == "oci" && record.operation == "get" && record.result == "miss")
        .expect("expected oci miss rollup");
    assert_eq!(miss_rollup.event_count, 1);

    let miss_key = missed
        .iter()
        .find(|record| record.tool == "oci")
        .expect("expected oci missed key");
    assert_eq!(miss_key.miss_count, 1);
}

use super::*;

#[tokio::test]
async fn test_nx_requires_bearer_auth() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/v1/cache/hash1")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_nx_put_head_get_round_trip() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxhash123";
    let payload = b"nx-cache-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", payload.len().to_string())
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    let expected_content_length = payload.len().to_string();
    assert_eq!(
        head_response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_content_length.as_str())
    );

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), payload);
}

#[tokio::test]
async fn test_nx_artifact_put_returns_conflict_for_existing_record() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxhashconflict";
    let first_payload = b"nx-first-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", first_payload.len().to_string())
            .body(Body::from(first_payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);

    let app = build_router(state.clone());
    let conflict_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", "14")
            .body(Body::from("second-payload"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(conflict_response.status(), StatusCode::CONFLICT);

    let app = build_router(state);
    let get_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(get_body.as_ref(), first_payload);
}

#[tokio::test]
async fn test_nx_query_returns_misses() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let hash = "nxtaskhash1";
    let payload = b"nx-query-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/cache/{hash}"))
            .header("authorization", "Bearer token")
            .header("content-length", payload.len().to_string())
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK);
    {
        let mut published = state.kv_published_index.write().await;
        published.set_empty();
    }

    let app = build_router(state);
    let query_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/v1/cache")
            .header("authorization", "Bearer token")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "hashes": [hash, "deadbeef"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(query_response.status(), StatusCode::OK);
    let body = query_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["misses"], json!(["deadbeef"]));
}

#[tokio::test]
async fn test_nx_artifact_get_miss_returns_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri("/v1/cache/missinghash")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_nx_terminal_output_get_and_head_misses_return_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let uri = "/v1/cache/missinghash/terminalOutputs";

    let get_response = tower::ServiceExt::oneshot(
        build_router(state.clone()),
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

    let head_response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(head_response.status(), StatusCode::NOT_FOUND);
    let head_body = head_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert!(head_body.is_empty());

    restore_mock.assert_async().await;
}

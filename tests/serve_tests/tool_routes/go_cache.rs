use super::*;

#[tokio::test]
async fn test_go_cache_put_head_get_round_trip() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;

    let action = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let payload = b"go-cache-payload";

    let app = build_router(state.clone());
    let put_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::PUT)
            .uri(format!("/gocache/{action}"))
            .body(Body::from(payload.to_vec()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(put_response.status(), StatusCode::CREATED);

    let app = build_router(state.clone());
    let head_response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::HEAD)
            .uri(format!("/gocache/{action}"))
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
            .uri(format!("/gocache/{action}"))
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
async fn test_go_cache_get_miss_returns_not_found() {
    let mut server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let restore_mock = mock_empty_cache_restore(&mut server, 2).await;
    let action = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let response = tower::ServiceExt::oneshot(
        build_router(state),
        Request::builder()
            .method(Method::GET)
            .uri(format!("/gocache/{action}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    restore_mock.assert_async().await;
}

#[tokio::test]
async fn test_go_cache_rejects_invalid_action_id() {
    let server = Server::new_async().await;
    let (state, _home, _guard) = setup(&server).await;
    let app = build_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/gocache/not-hex")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

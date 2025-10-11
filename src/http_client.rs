use reqwest::{header::HeaderMap, Client};
use std::time::Duration;

/// Build HTTP client for API requests with normal timeout
pub fn build_api_client_with_headers(headers: Option<HeaderMap>) -> Client {
    let is_test_mode = std::env::var("BORINGCACHE_TEST_MODE")
        .map(|value| value == "1")
        .unwrap_or(false);

    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(64)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .redirect(reqwest::redirect::Policy::limited(4))
        .use_rustls_tls();

    if is_test_mode {
        builder = builder
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_secs(2));
    } else {
        builder = builder
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
    }

    if let Some(headers) = headers {
        builder = builder.default_headers(headers);
    }

    builder.build().expect("Failed to build reqwest client")
}

/// Build a tuned HTTP client for uploads/downloads with optional custom headers
pub fn build_transfer_client_with_headers(headers: Option<HeaderMap>) -> Client {
    let is_test_mode = std::env::var("BORINGCACHE_TEST_MODE")
        .map(|value| value == "1")
        .unwrap_or(false);

    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(64)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::limited(4));

    if is_test_mode {
        builder = builder
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_secs(10));
    } else {
        builder = builder.timeout(Duration::from_secs(300));
    }

    if let Some(headers) = headers {
        builder = builder.default_headers(headers);
    }

    builder.build().expect("Failed to build reqwest client")
}

/// Build HTTP client for API requests
pub fn build_api_client() -> Client {
    build_api_client_with_headers(None)
}

/// Build a tuned HTTP client for uploads/downloads
pub fn build_transfer_client() -> Client {
    build_transfer_client_with_headers(None)
}

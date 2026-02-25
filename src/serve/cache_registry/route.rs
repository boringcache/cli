use axum::http::Method;

use super::error::RegistryError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryRoute {
    BazelAc { digest_hex: String },
    BazelCas { digest_hex: String },
    Gradle { cache_key: String },
    Maven { cache_key: String },
    NxArtifact { hash: String },
    NxTerminalOutput { hash: String },
    NxQuery,
    TurborepoStatus,
    TurborepoArtifact { hash: String },
    TurborepoQueryArtifacts,
    TurborepoEvents,
    SccacheObject { key_path: String },
    SccacheMkcol,
    GoCacheObject { action_hex: String },
}

pub(crate) fn detect_route(method: &Method, path: &str) -> Result<RegistryRoute, RegistryError> {
    let components = path_components(path);

    if is_turborepo_status_path(&components) {
        return Ok(RegistryRoute::TurborepoStatus);
    }

    if is_turborepo_query_path(&components) {
        return Ok(RegistryRoute::TurborepoQueryArtifacts);
    }

    if is_turborepo_events_path(&components) {
        return Ok(RegistryRoute::TurborepoEvents);
    }

    if let Some(hash) = parse_turbo_artifact_path(&components) {
        return Ok(RegistryRoute::TurborepoArtifact { hash });
    }

    if let Some(route) = parse_bazel_route(&components)? {
        return Ok(route);
    }

    if let Some(route) = parse_nx_route(&components)? {
        return Ok(route);
    }

    if let Some(cache_key) = parse_gradle_path(&components) {
        return Ok(RegistryRoute::Gradle { cache_key });
    }

    if let Some(cache_key) = parse_maven_path(&components) {
        return Ok(RegistryRoute::Maven { cache_key });
    }

    if method.as_str() == "MKCOL" {
        return Ok(RegistryRoute::SccacheMkcol);
    }

    if looks_like_sccache_key_path(&components) {
        return Ok(RegistryRoute::SccacheObject {
            key_path: path.to_string(),
        });
    }

    if let Some(action_hex) = parse_go_cache_path(&components)? {
        return Ok(RegistryRoute::GoCacheObject { action_hex });
    }

    Err(RegistryError::not_found("Route not found"))
}

fn parse_bazel_digest_path(raw: &str) -> Result<String, RegistryError> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RegistryError::bad_request(
            "Bazel cache key must be a 64-character hex sha256 digest",
        ));
    }
    Ok(raw.to_ascii_lowercase())
}

fn parse_bazel_route(components: &[&str]) -> Result<Option<RegistryRoute>, RegistryError> {
    if components.len() < 2 {
        return Ok(None);
    }
    let path_type = components[components.len() - 2];
    let digest_hex = components[components.len() - 1];
    if path_type != "ac" && path_type != "cas" {
        return Ok(None);
    }
    let digest_hex = parse_bazel_digest_path(digest_hex)?;
    if path_type == "ac" {
        Ok(Some(RegistryRoute::BazelAc { digest_hex }))
    } else {
        Ok(Some(RegistryRoute::BazelCas { digest_hex }))
    }
}

fn parse_gradle_path(components: &[&str]) -> Option<String> {
    if components.len() < 2 {
        return None;
    }
    let prefix = components[components.len() - 2];
    let cache_key = components[components.len() - 1];
    if prefix != "cache" || cache_key.is_empty() {
        return None;
    }
    Some(cache_key.to_string())
}

fn parse_maven_path(components: &[&str]) -> Option<String> {
    if components.len() < 5 {
        return None;
    }
    let version = components[components.len() - 5];
    if !is_maven_protocol_version(version) {
        return None;
    }
    let group_id = components[components.len() - 4];
    let artifact_id = components[components.len() - 3];
    let checksum = components[components.len() - 2];
    let filename = components[components.len() - 1];
    if group_id.is_empty() || artifact_id.is_empty() || checksum.is_empty() || filename.is_empty() {
        return None;
    }
    Some(format!(
        "{version}/{group_id}/{artifact_id}/{checksum}/{filename}"
    ))
}

fn is_maven_protocol_version(version: &str) -> bool {
    version == "v1" || version == "v1.1"
}

fn parse_nx_hash(raw: &str) -> Result<String, RegistryError> {
    if raw.is_empty()
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(RegistryError::bad_request(
            "Nx cache hash must contain only [A-Za-z0-9_-]",
        ));
    }
    Ok(raw.to_string())
}

fn parse_nx_route(components: &[&str]) -> Result<Option<RegistryRoute>, RegistryError> {
    if path_ends_with(components, &["v1", "cache"]) {
        return Ok(Some(RegistryRoute::NxQuery));
    }

    if components.len() >= 4
        && components[components.len() - 4] == "v1"
        && components[components.len() - 3] == "cache"
        && components[components.len() - 1] == "terminalOutputs"
    {
        let hash = parse_nx_hash(components[components.len() - 2])?;
        return Ok(Some(RegistryRoute::NxTerminalOutput { hash }));
    }

    if components.len() >= 3
        && components[components.len() - 3] == "v1"
        && components[components.len() - 2] == "cache"
    {
        let hash = parse_nx_hash(components[components.len() - 1])?;
        return Ok(Some(RegistryRoute::NxArtifact { hash }));
    }

    Ok(None)
}

fn parse_turbo_artifact_path(components: &[&str]) -> Option<String> {
    if components.len() < 2 {
        return None;
    }
    let marker = components[components.len() - 2];
    let hash = components[components.len() - 1];
    if marker != "artifacts" {
        return None;
    }
    if hash.eq_ignore_ascii_case("status") || hash.eq_ignore_ascii_case("events") {
        return None;
    }
    if !hash.is_empty() && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hash.to_ascii_lowercase())
    } else {
        None
    }
}

fn looks_like_sccache_key_path(components: &[&str]) -> bool {
    if components.len() < 4 {
        return false;
    }

    let shard_a = components[components.len() - 4];
    let shard_b = components[components.len() - 3];
    let shard_c = components[components.len() - 2];
    let key = components[components.len() - 1];

    [shard_a, shard_b, shard_c]
        .iter()
        .all(|part| part.len() == 1 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        && !key.is_empty()
        && key.bytes().all(|b| b.is_ascii_hexdigit())
        && key.len() >= 3
        && shard_a.eq_ignore_ascii_case(&key[0..1])
        && shard_b.eq_ignore_ascii_case(&key[1..2])
        && shard_c.eq_ignore_ascii_case(&key[2..3])
}

fn parse_go_action_id(raw: &str) -> Result<String, RegistryError> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RegistryError::bad_request(
            "Go cache action id must be a 64-character hex digest",
        ));
    }
    Ok(raw.to_ascii_lowercase())
}

fn parse_go_cache_path(components: &[&str]) -> Result<Option<String>, RegistryError> {
    if components.len() < 2 {
        return Ok(None);
    }
    let marker = components[components.len() - 2];
    if marker != "gocache" {
        return Ok(None);
    }
    let action_hex = parse_go_action_id(components[components.len() - 1])?;
    Ok(Some(action_hex))
}

fn path_components(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|component| !component.is_empty())
        .collect()
}

fn path_ends_with(components: &[&str], suffix: &[&str]) -> bool {
    components.len() >= suffix.len()
        && components[components.len() - suffix.len()..]
            .iter()
            .zip(suffix.iter())
            .all(|(left, right)| left == right)
}

fn is_turborepo_status_path(components: &[&str]) -> bool {
    path_ends_with(components, &["artifacts", "status"])
        || path_ends_with(components, &["v8", "artifacts", "status"])
}

fn is_turborepo_query_path(components: &[&str]) -> bool {
    path_ends_with(components, &["artifacts"]) || path_ends_with(components, &["v8", "artifacts"])
}

fn is_turborepo_events_path(components: &[&str]) -> bool {
    path_ends_with(components, &["artifacts", "events"])
        || path_ends_with(components, &["v8", "artifacts", "events"])
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn detect_route_accepts_bazel_ac_digest() {
        let route = detect_route(
            &Method::GET,
            "ac/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            route,
            RegistryRoute::BazelAc {
                digest_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string()
            }
        );
    }

    #[test]
    fn detect_route_rejects_invalid_bazel_digest() {
        let error = detect_route(&Method::GET, "ac/not-a-digest").unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn detect_route_accepts_sccache_sharded_path() {
        let route = detect_route(
            &Method::GET,
            "cache-prefix/0/1/2/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            route,
            RegistryRoute::SccacheObject {
                key_path:
                    "cache-prefix/0/1/2/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_mkcol_as_sccache_directory_create() {
        let method = Method::from_bytes(b"MKCOL").unwrap();
        let route = detect_route(&method, "any/path").unwrap();
        assert_eq!(route, RegistryRoute::SccacheMkcol);
    }

    #[test]
    fn detect_route_accepts_gradle_key_path() {
        let route = detect_route(&Method::GET, "cache/abcd1234").unwrap();
        assert_eq!(
            route,
            RegistryRoute::Gradle {
                cache_key: "abcd1234".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_turbo_v8_path() {
        let route = detect_route(&Method::GET, "v8/artifacts/abc123").unwrap();
        assert_eq!(
            route,
            RegistryRoute::TurborepoArtifact {
                hash: "abc123".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_maven_v11_path() {
        let route = detect_route(
            &Method::GET,
            "v1.1/com.example/app/abcdef1234567890/buildinfo.xml",
        )
        .unwrap();
        assert_eq!(
            route,
            RegistryRoute::Maven {
                cache_key: "v1.1/com.example/app/abcdef1234567890/buildinfo.xml".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_maven_v1_path() {
        let route = detect_route(
            &Method::GET,
            "v1/com.example/app/abcdef1234567890/buildinfo.xml",
        )
        .unwrap();
        assert_eq!(
            route,
            RegistryRoute::Maven {
                cache_key: "v1/com.example/app/abcdef1234567890/buildinfo.xml".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_prefixed_bazel_path() {
        let route = detect_route(
            &Method::GET,
            "cache/ac/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(
            route,
            RegistryRoute::BazelAc {
                digest_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string()
            }
        );
    }

    #[test]
    fn detect_route_rejects_non_hex_turbo_hash() {
        let error = detect_route(&Method::GET, "v8/artifacts/hash-123").unwrap_err();
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn detect_route_accepts_prefixed_gradle_path() {
        let route = detect_route(&Method::GET, "foo/cache/cache-key-1").unwrap();
        assert_eq!(
            route,
            RegistryRoute::Gradle {
                cache_key: "cache-key-1".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_prefixed_maven_path() {
        let route = detect_route(
            &Method::GET,
            "foo/bar/v1/com.example/app/abcdef1234567890/buildinfo.xml",
        )
        .unwrap();
        assert_eq!(
            route,
            RegistryRoute::Maven {
                cache_key: "v1/com.example/app/abcdef1234567890/buildinfo.xml".to_string()
            }
        );
    }

    #[test]
    fn detect_route_rejects_maven_path_with_unsupported_protocol_version() {
        let error = detect_route(
            &Method::GET,
            "v2/com.example/app/abcdef1234567890/buildinfo.xml",
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn detect_route_accepts_nx_artifact_path() {
        let route = detect_route(&Method::GET, "v1/cache/nx_hash-1").unwrap();
        assert_eq!(
            route,
            RegistryRoute::NxArtifact {
                hash: "nx_hash-1".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_nx_terminal_output_path() {
        let route = detect_route(&Method::GET, "v1/cache/nxhash/terminalOutputs").unwrap();
        assert_eq!(
            route,
            RegistryRoute::NxTerminalOutput {
                hash: "nxhash".to_string()
            }
        );
    }

    #[test]
    fn detect_route_accepts_nx_query_path() {
        let route = detect_route(&Method::POST, "v1/cache").unwrap();
        assert_eq!(route, RegistryRoute::NxQuery);
    }

    #[test]
    fn detect_route_rejects_invalid_nx_hash() {
        let error = detect_route(&Method::GET, "v1/cache/hash.with.dot").unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn detect_route_accepts_go_cache_path() {
        let action_hex =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let route = detect_route(&Method::GET, &format!("foo/gocache/{action_hex}")).unwrap();
        assert_eq!(route, RegistryRoute::GoCacheObject { action_hex });
    }

    #[test]
    fn detect_route_rejects_invalid_go_cache_path() {
        let error = detect_route(&Method::GET, "gocache/not-hex").unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn detect_route_rejects_sccache_path_with_invalid_shards() {
        let error = detect_route(
            &Method::GET,
            "prefix/0/1/2/f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }
}

use std::path::Path;

use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use tar::{Archive, Builder, EntryType};

use crate::serve::cache_registry::{
    KvNamespace, KvPutOptions, RegistryError, get_or_head_kv_object, put_kv_object,
    put_kv_object_with_options, resolve_kv_entries,
};
use crate::serve::state::AppState;

pub(crate) fn nx_artifact_put_options() -> KvPutOptions {
    KvPutOptions::default().with_existing_reject_status(StatusCode::CONFLICT)
}

pub(crate) async fn handle_artifact(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_bearer_header(headers)?;
    match method {
        Method::PUT => {
            validate_required_content_length(headers)?;
            let body = normalize_nx_artifact_body(body).await?;
            let _ = put_kv_object_with_options(
                state,
                KvNamespace::Nx,
                hash,
                body,
                StatusCode::OK,
                nx_artifact_put_options(),
            )
            .await?;
            Ok((StatusCode::OK, Body::empty()).into_response())
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(state, KvNamespace::Nx, hash, method == Method::HEAD).await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Nx artifact endpoint supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_terminal_output(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    hash: &str,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_bearer_header(headers)?;
    match method {
        Method::PUT => {
            let _ = put_kv_object(
                state,
                KvNamespace::NxTerminalOutput,
                hash,
                body,
                StatusCode::OK,
            )
            .await?;
            Ok((StatusCode::OK, Body::empty()).into_response())
        }
        Method::GET | Method::HEAD => {
            get_or_head_kv_object(
                state,
                KvNamespace::NxTerminalOutput,
                hash,
                method == Method::HEAD,
            )
            .await
        }
        _ => Err(RegistryError::method_not_allowed(
            "Nx terminal output endpoint supports GET, HEAD, and PUT",
        )),
    }
}

pub(crate) async fn handle_query(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, RegistryError> {
    ensure_bearer_header(headers)?;
    if method != Method::POST {
        return Err(RegistryError::method_not_allowed(
            "Nx cache query endpoint supports POST",
        ));
    }

    let bytes = axum::body::to_bytes(body, 512 * 1024)
        .await
        .map_err(|e| RegistryError::bad_request(format!("Invalid Nx query request body: {e}")))?;
    let request: NxQueryRequest = serde_json::from_slice(&bytes).map_err(|e| {
        RegistryError::bad_request(format!("Invalid Nx query request payload: {e}"))
    })?;
    let valid_hashes: Vec<&str> = request
        .hashes
        .iter()
        .filter(|hash| !hash.is_empty())
        .map(|hash| hash.as_str())
        .collect();

    let sizes = match resolve_kv_entries(state, KvNamespace::Nx, &valid_hashes).await {
        Ok(map) => map,
        Err(error) if error.status == StatusCode::NOT_FOUND => Default::default(),
        Err(error) => return Err(error),
    };

    let misses = request
        .hashes
        .into_iter()
        .filter(|hash| !hash.is_empty())
        .filter(|hash| !sizes.contains_key(&KvNamespace::Nx.scoped_key(hash)))
        .collect::<Vec<_>>();
    let payload = serde_json::to_string(&NxQueryResponse { misses }).map_err(|e| {
        RegistryError::internal(format!("Failed to serialize Nx query response: {e}"))
    })?;
    Ok((
        StatusCode::OK,
        [("Content-Type", "application/json")],
        payload,
    )
        .into_response())
}

fn ensure_bearer_header(headers: &HeaderMap) -> Result<(), RegistryError> {
    let value = headers.get("authorization").ok_or_else(|| {
        RegistryError::new(StatusCode::UNAUTHORIZED, "Missing Authorization header")
    })?;
    let value = value.to_str().map_err(|_| {
        RegistryError::new(StatusCode::UNAUTHORIZED, "Invalid Authorization header")
    })?;
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token = parts.next().map(str::trim).unwrap_or("");
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(RegistryError::new(
            StatusCode::UNAUTHORIZED,
            "Authorization header must be Bearer token",
        ));
    }
    Ok(())
}

fn validate_required_content_length(headers: &HeaderMap) -> Result<(), RegistryError> {
    let Some(value) = headers.get(header::CONTENT_LENGTH) else {
        return Err(RegistryError::bad_request(
            "Nx artifact uploads require Content-Length",
        ));
    };
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| RegistryError::bad_request("Invalid Content-Length header value"))?;
    Ok(())
}

async fn normalize_nx_artifact_body(body: Body) -> Result<Body, RegistryError> {
    let bytes = axum::body::to_bytes(body, crate::serve::state::max_spool_bytes() as usize)
        .await
        .map_err(|e| RegistryError::bad_request(format!("Invalid Nx artifact body: {e}")))?;
    if !looks_like_gzip(bytes.as_ref()) {
        return Ok(Body::from(bytes));
    }

    match strip_nx_reserved_output_directory_entries(bytes.as_ref()) {
        Ok(Some(normalized)) => Ok(Body::from(normalized)),
        Ok(None) => Ok(Body::from(bytes)),
        Err(error) => {
            log::debug!(
                "Leaving Nx artifact body unchanged after tar normalization failed: {error}"
            );
            Ok(Body::from(bytes))
        }
    }
}

fn looks_like_gzip(bytes: &[u8]) -> bool {
    matches!(bytes, [0x1f, 0x8b, ..])
}

fn strip_nx_reserved_output_directory_entries(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    // Nx 22.x appends metadata files named `code` and `terminalOutput` after
    // task outputs. A task output root directory with either name is redundant
    // for extraction, but Nx's reader treats it as metadata and can panic.
    let decoder = GzDecoder::new(bytes);
    let mut archive = Archive::new(decoder);
    let mut output = Vec::new();
    let encoder = GzEncoder::new(&mut output, Compression::default());
    let mut builder = Builder::new(encoder);
    let mut changed = false;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if is_nx_reserved_root_dir(&path, entry.header().entry_type()) {
            changed = true;
            continue;
        }

        let header = entry.header().clone();
        builder.append(&header, &mut entry)?;
    }

    let encoder = builder.into_inner()?;
    encoder.finish()?;

    Ok(changed.then_some(output))
}

fn is_nx_reserved_root_dir(path: &Path, entry_type: EntryType) -> bool {
    entry_type.is_dir() && (path == Path::new("code") || path == Path::new("terminalOutput"))
}

#[derive(serde::Deserialize)]
struct NxQueryRequest {
    hashes: Vec<String>,
}

#[derive(serde::Serialize)]
struct NxQueryResponse {
    misses: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    #[test]
    fn nx_artifact_put_rejects_existing_records_with_conflict() {
        let options = nx_artifact_put_options();
        assert_eq!(options.existing_reject_status(), Some(StatusCode::CONFLICT));
    }

    #[test]
    fn nx_artifact_normalizer_strips_reserved_root_directories_only() {
        let payload = nx_archive_with_reserved_output_directory();

        let normalized = strip_nx_reserved_output_directory_entries(&payload)
            .expect("normalizer should read nx tarball")
            .expect("normalizer should rewrite colliding root directory");
        let paths = tar_paths(&normalized);

        assert_eq!(
            paths,
            vec![
                "code/file.txt".to_string(),
                "terminalOutput".to_string(),
                "code".to_string(),
            ]
        );
        assert_eq!(metadata_code_bytes(&normalized), vec![0, 0, 0, 7]);
    }

    #[test]
    fn nx_artifact_normalizer_leaves_non_colliding_archive_unchanged() {
        let mut payload = Vec::new();
        {
            let encoder = GzEncoder::new(&mut payload, Compression::default());
            let mut builder = Builder::new(encoder);
            append_regular(&mut builder, "dist/file.txt", b"dist");
            let encoder = builder.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        assert!(
            strip_nx_reserved_output_directory_entries(&payload)
                .expect("normalizer should read nx tarball")
                .is_none()
        );
    }

    fn nx_archive_with_reserved_output_directory() -> Vec<u8> {
        let mut payload = Vec::new();
        {
            let encoder = GzEncoder::new(&mut payload, Compression::default());
            let mut builder = Builder::new(encoder);
            append_dir(&mut builder, "code");
            append_regular(&mut builder, "code/file.txt", b"artifact");
            append_regular(&mut builder, "terminalOutput", b"terminal");
            append_regular(&mut builder, "code", &[0, 0, 0, 7]);
            let encoder = builder.into_inner().unwrap();
            encoder.finish().unwrap();
        }
        payload
    }

    fn append_dir<W: Write>(builder: &mut Builder<W>, path: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(Vec::new()))
            .unwrap();
    }

    fn append_regular<W: Write>(builder: &mut Builder<W>, path: &str, data: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(data.to_vec()))
            .unwrap();
    }

    fn tar_paths(payload: &[u8]) -> Vec<String> {
        let decoder = GzDecoder::new(payload);
        let mut archive = Archive::new(decoder);
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    fn metadata_code_bytes(payload: &[u8]) -> Vec<u8> {
        let decoder = GzDecoder::new(payload);
        let mut archive = Archive::new(decoder);
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new("code") && entry.header().entry_type().is_file() {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                return bytes;
            }
        }
        panic!("metadata code entry not found");
    }
}

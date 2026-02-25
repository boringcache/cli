use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

const CAPABILITIES: [&str; 3] = ["get", "put", "close"];

pub async fn execute(endpoint: String, token: Option<String>, verbose: bool) -> Result<()> {
    let endpoint = normalize_endpoint(&endpoint)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("failed to build HTTP client for go-cacheprog")?;
    let session_dir = tempfile::tempdir().context("failed to allocate go-cacheprog temp dir")?;
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = BufWriter::new(tokio::io::stdout());

    write_response(
        &mut stdout,
        &json!({
            "ID": 0,
            "KnownCommands": CAPABILITIES,
        }),
    )
    .await?;

    let mut line = String::new();
    loop {
        line.clear();
        if stdin.read_line(&mut line).await? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request = parse_request_line(trimmed)?;
        let response = match request.command.as_str() {
            "get" => match handle_get(
                &client,
                &endpoint,
                token.as_deref(),
                &request,
                session_dir.path(),
                verbose,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => response_error(request.id, error),
            },
            "put" => match handle_put(
                &client,
                &endpoint,
                token.as_deref(),
                &request,
                &mut stdin,
                session_dir.path(),
                verbose,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => response_error(request.id, error),
            },
            "close" => {
                if verbose {
                    eprintln!("go-cacheprog close");
                }
                write_response(&mut stdout, &json!({ "ID": request.id })).await?;
                break;
            }
            _ => response_error(
                request.id,
                anyhow!("unsupported command '{}'", request.command),
            ),
        };

        write_response(&mut stdout, &response).await?;
    }

    Ok(())
}

#[derive(Debug)]
struct ParsedRequest {
    id: i64,
    command: String,
    action_id: Option<Vec<u8>>,
    body_size: u64,
}

fn parse_request_line(line: &str) -> Result<ParsedRequest> {
    let value: Value = serde_json::from_str(line).context("invalid go-cacheprog request JSON")?;
    let id = value
        .get("ID")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("request is missing numeric ID"))?;
    let command = value
        .get("Command")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("request is missing Command"))?
        .to_ascii_lowercase();
    let action_id = value
        .get("ActionID")
        .map(decode_base64_json_value)
        .transpose()?;
    let body_size = value.get("BodySize").and_then(Value::as_u64).unwrap_or(0);

    Ok(ParsedRequest {
        id,
        command,
        action_id,
        body_size,
    })
}

fn decode_base64_json_value(value: &Value) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .ok_or_else(|| anyhow!("expected base64 string"))?;
    STANDARD
        .decode(encoded.as_bytes())
        .map_err(|error| anyhow!("invalid base64 value: {error}"))
}

async fn handle_get(
    client: &reqwest::Client,
    endpoint: &str,
    token: Option<&str>,
    request: &ParsedRequest,
    session_dir: &Path,
    verbose: bool,
) -> Result<Value> {
    let action_hex = request_action_hex(request)?;
    let url = build_go_cache_url(endpoint, &action_hex);
    let mut http_request = client.get(url);
    if let Some(token) = token {
        http_request = http_request.bearer_auth(token);
    }
    let response = http_request
        .send()
        .await
        .context("go-cacheprog GET request failed")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        if verbose {
            eprintln!("go-cacheprog get miss action={action_hex}");
        }
        return Ok(json!({
            "ID": request.id,
            "Miss": true
        }));
    }
    if !response.status().is_success() {
        bail!("go-cache endpoint returned {}", response.status());
    }

    let body = response
        .bytes()
        .await
        .context("failed to read go-cache response body")?;
    let disk_path = session_file_path(session_dir, request.id, &action_hex);
    tokio::fs::write(&disk_path, &body)
        .await
        .context("failed to write go-cache body to disk")?;
    let output_id = Sha256::digest(&body);
    if verbose {
        eprintln!(
            "go-cacheprog get hit action={action_hex} size={}",
            body.len()
        );
    }

    Ok(json!({
        "ID": request.id,
        "Miss": false,
        "OutputID": STANDARD.encode(output_id),
        "Size": body.len(),
        "DiskPath": disk_path.to_string_lossy().to_string(),
    }))
}

async fn handle_put(
    client: &reqwest::Client,
    endpoint: &str,
    token: Option<&str>,
    request: &ParsedRequest,
    stdin: &mut BufReader<tokio::io::Stdin>,
    session_dir: &Path,
    verbose: bool,
) -> Result<Value> {
    let action_hex = request_action_hex(request)?;
    let body = read_request_body(stdin, request.body_size).await?;
    let url = build_go_cache_url(endpoint, &action_hex);
    let mut http_request = client.put(url).body(body.clone());
    if let Some(token) = token {
        http_request = http_request.bearer_auth(token);
    }
    let response = http_request
        .send()
        .await
        .context("go-cacheprog PUT request failed")?;
    if !response.status().is_success() {
        bail!("go-cache endpoint returned {}", response.status());
    }

    let disk_path = session_file_path(session_dir, request.id, &action_hex);
    tokio::fs::write(&disk_path, &body)
        .await
        .context("failed to write go-cache body to disk")?;
    if verbose {
        eprintln!(
            "go-cacheprog put ok action={action_hex} size={}",
            body.len()
        );
    }

    Ok(json!({
        "ID": request.id,
        "DiskPath": disk_path.to_string_lossy().to_string(),
    }))
}

fn request_action_hex(request: &ParsedRequest) -> Result<String> {
    let action_id = request
        .action_id
        .as_ref()
        .ok_or_else(|| anyhow!("request is missing ActionID"))?;
    if action_id.len() != 32 {
        bail!("ActionID must be exactly 32 bytes, got {}", action_id.len());
    }
    Ok(hex::encode(action_id))
}

async fn read_request_body(
    stdin: &mut BufReader<tokio::io::Stdin>,
    expected_size: u64,
) -> Result<Vec<u8>> {
    if expected_size == 0 {
        return Ok(Vec::new());
    }

    let mut body_line = String::new();
    loop {
        body_line.clear();
        if stdin.read_line(&mut body_line).await? == 0 {
            bail!("unexpected EOF while reading go-cacheprog body");
        }
        if !body_line.trim().is_empty() {
            break;
        }
    }

    let encoded: String = serde_json::from_str(body_line.trim())
        .context("invalid go-cacheprog body encoding (expected JSON string)")?;
    let decoded = STANDARD
        .decode(encoded.as_bytes())
        .context("invalid go-cacheprog body base64 payload")?;
    if decoded.len() as u64 != expected_size {
        bail!(
            "go-cacheprog body size mismatch: expected {}, got {}",
            expected_size,
            decoded.len()
        );
    }
    Ok(decoded)
}

fn normalize_endpoint(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim().trim_end_matches('/').to_string();
    if endpoint.is_empty() {
        bail!("go-cacheprog endpoint must not be empty");
    }
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        bail!("go-cacheprog endpoint must start with http:// or https://");
    }
    Ok(endpoint)
}

fn build_go_cache_url(endpoint: &str, action_hex: &str) -> String {
    format!("{endpoint}/gocache/{action_hex}")
}

fn session_file_path(session_dir: &Path, request_id: i64, action_hex: &str) -> PathBuf {
    session_dir.join(format!("{}-{}.bin", request_id, &action_hex[..16]))
}

fn response_error(id: i64, error: anyhow::Error) -> Value {
    json!({
        "ID": id,
        "Err": error.to_string(),
    })
}

async fn write_response(stdout: &mut BufWriter<tokio::io::Stdout>, value: &Value) -> Result<()> {
    let line = serde_json::to_string(value).context("failed to serialize go-cacheprog response")?;
    stdout.write_all(line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_line_decodes_action_id() {
        let action_id = [7u8; 32];
        let line = json!({
            "ID": 9,
            "Command": "get",
            "ActionID": STANDARD.encode(action_id),
        })
        .to_string();
        let parsed = parse_request_line(&line).unwrap();
        assert_eq!(parsed.id, 9);
        assert_eq!(parsed.command, "get");
        assert_eq!(parsed.action_id.unwrap(), action_id);
        assert_eq!(parsed.body_size, 0);
    }

    #[test]
    fn parse_request_line_rejects_missing_id() {
        let line = json!({
            "Command": "get",
        })
        .to_string();
        let error = parse_request_line(&line).unwrap_err();
        assert!(error.to_string().contains("missing numeric ID"));
    }

    #[test]
    fn normalize_endpoint_rejects_invalid_scheme() {
        let error = normalize_endpoint("localhost:5000").unwrap_err();
        assert!(error
            .to_string()
            .contains("must start with http:// or https://"));
    }

    #[test]
    fn request_action_hex_requires_32_bytes() {
        let request = ParsedRequest {
            id: 1,
            command: "get".to_string(),
            action_id: Some(vec![1u8; 31]),
            body_size: 0,
        };
        let error = request_action_hex(&request).unwrap_err();
        assert!(error.to_string().contains("must be exactly 32 bytes"));
    }

    #[test]
    fn build_go_cache_url_appends_action() {
        let url = build_go_cache_url("http://127.0.0.1:5000", &"a".repeat(64));
        assert!(url.ends_with(&format!("/gocache/{}", "a".repeat(64))));
    }
}

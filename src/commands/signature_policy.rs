use anyhow::{Context, Result};

use crate::api::CacheResolutionEntry;

pub(crate) fn signature_subject_tag<'a>(
    hit: &'a CacheResolutionEntry,
    manifest_tag: Option<&'a str>,
) -> &'a str {
    hit.signature_tag
        .as_deref()
        .or(manifest_tag)
        .or(hit.primary_tag.as_deref())
        .unwrap_or(hit.tag.as_str())
}

pub(crate) fn signature_display_tag<'a>(
    hit: &'a CacheResolutionEntry,
    fallback: &'a str,
) -> &'a str {
    hit.signature_tag
        .as_deref()
        .or(hit.primary_tag.as_deref())
        .unwrap_or(fallback)
}

pub(crate) fn verify_server_signature(
    tag: &str,
    root_digest: &str,
    workspace_signing_public_key: &str,
    server_signature: &str,
) -> Result<()> {
    let public_key = crate::signing::parse_public_key(workspace_signing_public_key)
        .context("Failed to parse workspace signing public key")?;
    let signature = crate::signing::signature_from_base64(server_signature)
        .context("Failed to parse server signature")?;
    let data_to_verify = format!("{}:{}", tag, root_digest);

    crate::signing::verify_signature(data_to_verify.as_bytes(), &signature, &public_key)
        .context("Server signature verification failed")?;
    Ok(())
}

pub(crate) fn verify_restore_signature(
    hit: &CacheResolutionEntry,
    root_digest: &str,
    manifest_tag: Option<&str>,
    verbose: bool,
    reporter: Option<&crate::progress::Reporter>,
    require_server_signature: bool,
) -> Result<()> {
    let signature_tag = signature_subject_tag(hit, manifest_tag);
    let display_tag = signature_display_tag(hit, manifest_tag.unwrap_or(hit.tag.as_str()));

    match (&hit.workspace_signing_public_key, &hit.server_signature) {
        (Some(workspace_key), Some(server_sig)) => {
            match verify_server_signature(signature_tag, root_digest, workspace_key, server_sig) {
                Ok(()) => {
                    if verbose {
                        let public_key = crate::signing::parse_public_key(workspace_key).ok();
                        let fingerprint = public_key
                            .as_ref()
                            .map(crate::signing::public_key_fingerprint)
                            .unwrap_or_else(|| "unknown".to_string());
                        if let Some(reporter) = reporter {
                            let _ = reporter
                                .info(format!("  Server signature verified ({})", fingerprint));
                        }
                    }
                    Ok(())
                }
                Err(error) => signature_policy_failure(
                    format!(
                        "Server signature verification failed for {}: {}",
                        display_tag, error
                    ),
                    require_server_signature,
                ),
            }
        }
        (Some(_), None) => signature_policy_failure(
            format!(
                "Server signature missing for {}; authenticity not verified",
                display_tag
            ),
            require_server_signature,
        ),
        (None, Some(_)) => signature_policy_failure(
            format!(
                "Workspace signing key missing for {}; cannot verify server signature",
                display_tag
            ),
            require_server_signature,
        ),
        (None, None) => signature_policy_failure(
            format!(
                "Server signature missing for {}; authenticity not verified",
                display_tag
            ),
            require_server_signature,
        ),
    }
}

pub(crate) fn enforce_server_signature(
    hit: &CacheResolutionEntry,
    root_digest: &str,
    manifest_tag: Option<&str>,
    verbose: bool,
    require_server_signature: bool,
) -> Result<()> {
    verify_restore_signature(
        hit,
        root_digest,
        manifest_tag,
        verbose,
        None,
        require_server_signature,
    )
}

fn signature_policy_failure(message: String, require_server_signature: bool) -> Result<()> {
    if require_server_signature {
        anyhow::bail!(message);
    }

    crate::ui::warn(&message);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_subject_prefers_explicit_signature_tag() {
        let hit = CacheResolutionEntry {
            tag: "fallback".to_string(),
            primary_tag: Some("primary".to_string()),
            signature_tag: Some("signature".to_string()),
            status: "hit".to_string(),
            cache_entry_id: None,
            manifest_url: None,
            manifest_root_digest: None,
            manifest_digest: None,
            compression_algorithm: None,
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            content_hash: None,
            pending: false,
            error: None,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        };

        assert_eq!(signature_subject_tag(&hit, Some("manifest")), "signature");
        assert_eq!(signature_display_tag(&hit, "fallback"), "signature");
    }
}

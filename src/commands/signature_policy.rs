use anyhow::{Context, Result};

use crate::api::CacheResolutionEntry;

fn signature_subject_tag<'a>(
    hit: &'a CacheResolutionEntry,
    manifest_tag: Option<&'a str>,
) -> &'a str {
    hit.signature_tag
        .as_deref()
        .or(manifest_tag)
        .or(hit.primary_tag.as_deref())
        .unwrap_or(hit.tag.as_str())
}

fn signature_display_tag<'a>(hit: &'a CacheResolutionEntry, fallback: &'a str) -> &'a str {
    hit.signature_tag
        .as_deref()
        .or(hit.primary_tag.as_deref())
        .unwrap_or(fallback)
}

fn signature_policy_failure(message: String, require_server_signature: bool) -> Result<()> {
    if require_server_signature {
        anyhow::bail!(message);
    }

    crate::ui::warn(&message);
    Ok(())
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

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

use crate::api::CacheResolutionEntry;

const SIGNATURE_ENVELOPE_TYPE: &str = "com.boringcache.cache-entry.v1";
const TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV: &str = "BORINGCACHE_TRUSTED_WORKSPACE_KEY_FINGERPRINT";

#[derive(Debug, Deserialize)]
struct CacheEntrySignatureEnvelope {
    #[serde(rename = "type")]
    envelope_type: String,
    workspace_id: String,
    cache_entry_id: String,
    tag: String,
    manifest_root_digest: String,
    storage_mode: String,
    finalized_at: String,
    signed_at: String,
    key_id: String,
}

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

pub(crate) fn verify_cache_entry_signature(
    hit: &CacheResolutionEntry,
    root_digest: &str,
    manifest_tag: Option<&str>,
) -> Result<()> {
    let signature_tag = signature_subject_tag(hit, manifest_tag);
    let workspace_key = hit.workspace_signing_public_key.as_deref().ok_or_else(|| {
        anyhow!(
            "Workspace signing key missing for {}; strict signature mode is enabled",
            signature_tag
        )
    })?;
    let server_signature = hit.server_signature.as_deref().ok_or_else(|| {
        anyhow!(
            "Server signature missing for {}; strict signature mode is enabled",
            signature_tag
        )
    })?;

    if let Some(payload) = hit.server_signature_payload.as_deref() {
        verify_enveloped_signature(
            hit,
            signature_tag,
            root_digest,
            workspace_key,
            server_signature,
            payload,
        )
    } else {
        verify_workspace_key_trust(hit, workspace_key)?;
        verify_server_signature(signature_tag, root_digest, workspace_key, server_signature)
    }
}

pub(crate) fn verify_restore_signature(
    hit: &CacheResolutionEntry,
    root_digest: &str,
    manifest_tag: Option<&str>,
    verbose: bool,
    reporter: Option<&crate::progress::Reporter>,
    require_server_signature: bool,
) -> Result<()> {
    let display_tag = signature_display_tag(hit, manifest_tag.unwrap_or(hit.tag.as_str()));

    match (&hit.workspace_signing_public_key, &hit.server_signature) {
        (Some(workspace_key), Some(_)) => {
            match verify_cache_entry_signature(hit, root_digest, manifest_tag) {
                Ok(()) => {
                    if verbose {
                        let public_key = crate::signing::parse_public_key(workspace_key).ok();
                        let fingerprint = public_key
                            .as_ref()
                            .map(crate::signing::public_key_pin_fingerprint)
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

fn verify_enveloped_signature(
    hit: &CacheResolutionEntry,
    signature_tag: &str,
    root_digest: &str,
    workspace_signing_public_key: &str,
    server_signature: &str,
    payload: &str,
) -> Result<()> {
    let public_key = verify_workspace_key_trust(hit, workspace_signing_public_key)?;
    let signature = crate::signing::signature_from_base64(server_signature)
        .context("Failed to parse server signature")?;

    crate::signing::verify_signature(payload.as_bytes(), &signature, &public_key)
        .context("Server signature verification failed")?;

    let envelope: CacheEntrySignatureEnvelope =
        serde_json::from_str(payload).context("Failed to parse server signature payload")?;
    let expected_key_id = crate::signing::public_key_pin_fingerprint(&public_key);
    verify_envelope_matches_entry(hit, &envelope, signature_tag, root_digest, &expected_key_id)?;
    Ok(())
}

fn verify_workspace_key_trust(
    hit: &CacheResolutionEntry,
    workspace_signing_public_key: &str,
) -> Result<ed25519_dalek::VerifyingKey> {
    let public_key = crate::signing::parse_public_key(workspace_signing_public_key)
        .context("Failed to parse workspace signing public key")?;
    let fingerprint = crate::signing::public_key_pin_fingerprint(&public_key);

    if let Some(reported) = hit.workspace_signing_key_fingerprint.as_deref()
        && reported != fingerprint
    {
        anyhow::bail!(
            "Workspace signing key fingerprint mismatch: response reported {}, computed {}",
            reported,
            fingerprint
        );
    }

    if let Some(trusted) = trusted_workspace_key_fingerprints()
        && !trusted.iter().any(|candidate| candidate == &fingerprint)
    {
        anyhow::bail!(
            "Workspace signing key {} does not match trusted fingerprint {}",
            fingerprint,
            trusted.join(", ")
        );
    }

    Ok(public_key)
}

fn verify_envelope_matches_entry(
    hit: &CacheResolutionEntry,
    envelope: &CacheEntrySignatureEnvelope,
    signature_tag: &str,
    root_digest: &str,
    expected_key_id: &str,
) -> Result<()> {
    if envelope.envelope_type != SIGNATURE_ENVELOPE_TYPE {
        anyhow::bail!(
            "Unexpected server signature payload type {}",
            envelope.envelope_type
        );
    }
    if envelope.workspace_id.trim().is_empty() {
        anyhow::bail!("Server signature payload is missing workspace_id");
    }
    if envelope.finalized_at.trim().is_empty() {
        anyhow::bail!("Server signature payload is missing finalized_at");
    }
    if envelope.signed_at.trim().is_empty() {
        anyhow::bail!("Server signature payload is missing signed_at");
    }
    if envelope.key_id.trim().is_empty() {
        anyhow::bail!("Server signature payload is missing key_id");
    }
    if envelope.key_id != expected_key_id {
        anyhow::bail!(
            "Server signature payload key id {} does not match workspace key id {}",
            envelope.key_id,
            expected_key_id
        );
    }
    if let Some(cache_entry_id) = hit.cache_entry_id.as_deref()
        && envelope.cache_entry_id != cache_entry_id
    {
        anyhow::bail!(
            "Server signature payload entry id {} does not match response entry id {}",
            envelope.cache_entry_id,
            cache_entry_id
        );
    }
    if envelope.tag != signature_tag {
        anyhow::bail!(
            "Server signature payload tag {} does not match response tag {}",
            envelope.tag,
            signature_tag
        );
    }
    if envelope.manifest_root_digest != root_digest {
        anyhow::bail!(
            "Server signature payload root {} does not match response root {}",
            envelope.manifest_root_digest,
            root_digest
        );
    }
    if let Some(storage_mode) = hit.storage_mode.as_deref()
        && envelope.storage_mode != storage_mode
    {
        anyhow::bail!(
            "Server signature payload storage mode {} does not match response storage mode {}",
            envelope.storage_mode,
            storage_mode
        );
    }
    if let Some(server_key_id) = hit.server_signing_key_id.as_deref()
        && envelope.key_id != server_key_id
    {
        anyhow::bail!(
            "Server signature payload key id {} does not match response key id {}",
            envelope.key_id,
            server_key_id
        );
    }

    Ok(())
}

fn trusted_workspace_key_fingerprints() -> Option<Vec<String>> {
    let value = crate::config::env_var(TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV)?;
    let fingerprints = value
        .split(|ch: char| ch == ',' || ch == '\n' || ch.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    (!fingerprints.is_empty()).then_some(fingerprints)
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

    fn base_hit() -> CacheResolutionEntry {
        CacheResolutionEntry {
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
            workspace_signing_key_fingerprint: None,
            server_signature: None,
            server_signature_payload: None,
            server_signature_version: None,
            server_signing_key_id: None,
            server_signed_at: None,
            encrypted: false,
        }
    }

    fn signed_envelope_hit(root_digest: &str) -> CacheResolutionEntry {
        let (signing_key, verifying_key) = crate::signing::generate_keypair();
        let public_key = crate::signing::format_public_key(&verifying_key);
        let key_id = crate::signing::public_key_pin_fingerprint(&verifying_key);
        let payload = format!(
            "{{\"type\":\"{}\",\"workspace_id\":\"workspace-1\",\"cache_entry_id\":\"entry-1\",\"tag\":\"deps\",\"manifest_root_digest\":\"{}\",\"storage_mode\":\"archive\",\"finalized_at\":\"2026-04-28T12:00:00.000000Z\",\"signed_at\":\"2026-04-28T12:00:01.000000Z\",\"key_id\":\"{}\"}}",
            SIGNATURE_ENVELOPE_TYPE, root_digest, key_id
        );
        let signature = crate::signing::signature_to_base64(&crate::signing::sign_data(
            payload.as_bytes(),
            &signing_key,
        ));

        CacheResolutionEntry {
            tag: "deps".to_string(),
            primary_tag: None,
            signature_tag: Some("deps".to_string()),
            status: "hit".to_string(),
            cache_entry_id: Some("entry-1".to_string()),
            manifest_url: None,
            manifest_root_digest: Some(root_digest.to_string()),
            manifest_digest: None,
            compression_algorithm: None,
            storage_mode: Some("archive".to_string()),
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
            workspace_signing_public_key: Some(public_key),
            workspace_signing_key_fingerprint: Some(key_id.clone()),
            server_signature: Some(signature),
            server_signature_payload: Some(payload),
            server_signature_version: Some(1),
            server_signing_key_id: Some(key_id),
            server_signed_at: Some("2026-04-28T12:00:01Z".to_string()),
            encrypted: false,
        }
    }

    #[test]
    fn signature_subject_prefers_explicit_signature_tag() {
        let hit = base_hit();

        assert_eq!(signature_subject_tag(&hit, Some("manifest")), "signature");
        assert_eq!(signature_display_tag(&hit, "fallback"), "signature");
    }

    #[test]
    fn verifies_enveloped_signature_with_trusted_fingerprint() {
        let _guard = crate::test_env::lock();
        crate::test_env::remove_var(TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV);
        let root_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hit = signed_envelope_hit(root_digest);
        crate::test_env::set_var(
            TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV,
            hit.workspace_signing_key_fingerprint.as_deref().unwrap(),
        );

        verify_cache_entry_signature(&hit, root_digest, None).unwrap();
        crate::test_env::remove_var(TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV);
    }

    #[test]
    fn rejects_untrusted_workspace_key_fingerprint() {
        let _guard = crate::test_env::lock();
        crate::test_env::remove_var(TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV);
        let root_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let hit = signed_envelope_hit(root_digest);
        crate::test_env::set_var(
            TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV,
            "ed25519-sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );

        let error = verify_cache_entry_signature(&hit, root_digest, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match trusted fingerprint")
        );
        crate::test_env::remove_var(TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV);
    }

    #[test]
    fn rejects_envelope_root_mismatch() {
        let _guard = crate::test_env::lock();
        crate::test_env::remove_var(TRUSTED_WORKSPACE_KEY_FINGERPRINT_ENV);
        let signed_root = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let expected_root =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let hit = signed_envelope_hit(signed_root);

        let error = verify_cache_entry_signature(&hit, expected_root, None).unwrap_err();
        assert!(error.to_string().contains("does not match response root"));
    }
}

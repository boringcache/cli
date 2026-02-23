use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

pub const SIGNING_ALGORITHM: &str = "ed25519";

#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub signing_key_path: Option<String>,
    pub verify: bool,
    pub trusted_keys: Vec<String>,
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let contents = std::fs::read(path)
        .with_context(|| format!("Failed to read signing key: {}", path.display()))?;

    if contents.len() == 32 {
        let bytes: [u8; 32] = contents
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signing key length"))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }

    let decoded = if let Ok(s) = std::str::from_utf8(&contents) {
        let trimmed = s.trim();
        if trimmed.starts_with("ed25519:") {
            let encoded = trimmed
                .strip_prefix("ed25519:")
                .ok_or_else(|| anyhow::anyhow!("Invalid ed25519 signing key prefix"))?;
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                .context("Failed to decode base64 signing key")?
        } else {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
                .context("Failed to decode base64 signing key")?
        }
    } else {
        contents
    };

    if decoded.len() != 32 {
        anyhow::bail!(
            "Invalid signing key: expected 32 bytes, got {}",
            decoded.len()
        );
    }

    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signing key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn save_signing_key(key: &SigningKey, path: &Path) -> Result<()> {
    let parent = path.parent();
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
    }

    std::fs::write(path, key.to_bytes())
        .with_context(|| format!("Failed to write signing key: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("Failed to set permissions on: {}", path.display()))?;
    }

    Ok(())
}

pub fn parse_public_key(key_str: &str) -> Result<VerifyingKey> {
    let key_data = if key_str.starts_with("ed25519:") {
        key_str
            .strip_prefix("ed25519:")
            .ok_or_else(|| anyhow::anyhow!("Invalid public key prefix"))?
    } else {
        key_str
    };

    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_data)
        .context("Failed to decode base64 public key")?;

    if bytes.len() != 32 {
        anyhow::bail!("Invalid public key: expected 32 bytes, got {}", bytes.len());
    }

    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;

    VerifyingKey::from_bytes(&bytes).context("Invalid Ed25519 public key")
}

pub fn format_public_key(key: &VerifyingKey) -> String {
    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_bytes());
    format!("ed25519:{}", encoded)
}

pub fn sign_data(data: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(data)
}

pub fn verify_signature(
    data: &[u8],
    signature: &Signature,
    public_key: &VerifyingKey,
) -> Result<()> {
    public_key
        .verify(data, signature)
        .context("Signature verification failed")
}

pub fn signature_to_base64(signature: &Signature) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    )
}

pub fn signature_from_base64(encoded: &str) -> Result<Signature> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .context("Failed to decode signature")?;

    if bytes.len() != 64 {
        anyhow::bail!("Invalid signature: expected 64 bytes, got {}", bytes.len());
    }

    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

    Ok(Signature::from_bytes(&bytes))
}

pub fn public_key_fingerprint(key: &VerifyingKey) -> String {
    let full = format_public_key(key);
    if full.len() > 20 {
        format!("{}...{}", &full[..12], &full[full.len() - 4..])
    } else {
        full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let data = b"Hello, World! This is test data to sign.";

        let signature = sign_data(data, &signing_key);
        assert!(verify_signature(data, &signature, &verifying_key).is_ok());

        let wrong_data = b"Wrong data";
        assert!(verify_signature(wrong_data, &signature, &verifying_key).is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let (signing_key, _) = generate_keypair();
        let data = b"Test data";

        let signature = sign_data(data, &signing_key);
        let encoded = signature_to_base64(&signature);
        let decoded = signature_from_base64(&encoded).unwrap();

        assert_eq!(signature, decoded);
    }

    #[test]
    fn test_public_key_serialization() {
        let (_, verifying_key) = generate_keypair();

        let formatted = format_public_key(&verifying_key);
        assert!(formatted.starts_with("ed25519:"));

        let parsed = parse_public_key(&formatted).unwrap();
        assert_eq!(verifying_key, parsed);
    }

    #[test]
    fn test_public_key_fingerprint() {
        let (_, verifying_key) = generate_keypair();
        let fingerprint = public_key_fingerprint(&verifying_key);

        assert!(fingerprint.contains("..."));
        assert!(fingerprint.starts_with("ed25519:"));
    }
}

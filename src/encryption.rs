use age::secrecy::SecretString;
use anyhow::{Context, Result};
use std::io::{Cursor, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const ENCRYPTION_ALGORITHM_AGE_X25519: &str = "age-x25519";
pub const ENCRYPTION_ALGORITHM_AGE_SCRYPT: &str = "age-scrypt";
const AGE_MAGIC: &[u8] = b"age-encryption.org/";

#[derive(Debug, thiserror::Error)]
#[error("Encrypted data requires an identity file; use --identity or configure a default")]
pub struct IdentityRequired;

#[derive(Debug, thiserror::Error)]
#[error("Encrypted data requires a passphrase")]
pub struct PassphraseRequired;

#[derive(Debug, Default)]
pub struct PassphraseCache {
    prompted: bool,
    value: Option<Arc<SecretString>>,
}

pub fn cached_passphrase(cache: &Arc<Mutex<PassphraseCache>>) -> Result<Option<Arc<SecretString>>> {
    let guard = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("Passphrase cache lock poisoned"))?;
    Ok(guard.value.clone())
}

pub fn get_or_prompt_passphrase(
    cache: &Arc<Mutex<PassphraseCache>>,
    prompt: &str,
) -> Result<Option<Arc<SecretString>>> {
    {
        let guard = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Passphrase cache lock poisoned"))?;
        if guard.prompted {
            return Ok(guard.value.clone());
        }
    }

    if !std::io::stdin().is_terminal() {
        let mut guard = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Passphrase cache lock poisoned"))?;
        guard.prompted = true;
        return Ok(None);
    }

    let passphrase = prompt_optional_passphrase(prompt)?.map(Arc::new);
    let mut guard = cache
        .lock()
        .map_err(|_| anyhow::anyhow!("Passphrase cache lock poisoned"))?;
    guard.prompted = true;
    guard.value = passphrase.clone();
    Ok(passphrase)
}

pub fn is_passphrase_required(err: &anyhow::Error) -> bool {
    err.downcast_ref::<PassphraseRequired>().is_some()
}

#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub recipient: String,
    pub identity_path: Option<String>,
}

pub fn parse_recipient(recipient: &str) -> Result<age::x25519::Recipient> {
    recipient
        .parse::<age::x25519::Recipient>()
        .map_err(|e| anyhow::anyhow!("Invalid Age recipient public key: {}", e))
}

pub fn load_identity(path: &Path) -> Result<age::x25519::Identity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).with_context(|| {
            format!("Failed to read identity file metadata: {}", path.display())
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "Insecure permissions on identity file {} (mode {:o}); run chmod 600",
                path.display(),
                mode
            );
        }
    }

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read identity file: {}", path.display()))?;

    let identity = contents
        .parse::<age::x25519::Identity>()
        .map_err(|e| anyhow::anyhow!("Invalid Age identity file: {}", e))?;

    Ok(identity)
}

pub fn generate_keypair() -> (age::x25519::Identity, age::x25519::Recipient) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

pub fn identity_to_recipient(identity: &age::x25519::Identity) -> Result<age::x25519::Recipient> {
    Ok(identity.to_public())
}

pub fn encrypt_data(data: &[u8], recipient: &age::x25519::Recipient) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .expect("Failed to create encryptor");

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("Failed to initialize encryption")?;

    writer.write_all(data).context("Failed to encrypt data")?;
    writer.finish().context("Failed to finalize encryption")?;

    Ok(encrypted)
}

pub fn decrypt_data(encrypted: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor =
        match age::Decryptor::new(encrypted).context("Failed to parse encrypted data")? {
            age::Decryptor::Recipients(d) => d,
            _ => anyhow::bail!("Unexpected encryption format"),
        };

    let mut decrypted = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .context("Failed to decrypt data (wrong key?)")?;

    reader
        .read_to_end(&mut decrypted)
        .context("Failed to read decrypted data")?;

    Ok(decrypted)
}

pub fn decrypt_bytes(
    encrypted: &[u8],
    identity: Option<&age::x25519::Identity>,
    passphrase: Option<&SecretString>,
) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    decrypt_stream(Cursor::new(encrypted), &mut decrypted, identity, passphrase)?;
    Ok(decrypted)
}

pub fn encrypt_stream<R: Read, W: Write>(
    mut input: R,
    output: W,
    recipient: &age::x25519::Recipient,
) -> Result<u64> {
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .expect("Failed to create encryptor");

    let mut writer = encryptor
        .wrap_output(output)
        .context("Failed to initialize encryption")?;

    let bytes_written =
        std::io::copy(&mut input, &mut writer).context("Failed to encrypt stream")?;

    writer.finish().context("Failed to finalize encryption")?;

    Ok(bytes_written)
}

pub fn decrypt_stream<R: Read, W: Write>(
    input: R,
    mut output: W,
    identity: Option<&age::x25519::Identity>,
    passphrase: Option<&SecretString>,
) -> Result<u64> {
    let decryptor = match age::Decryptor::new(input).context("Failed to parse encrypted data")? {
        age::Decryptor::Recipients(d) => {
            let identity = identity.ok_or(IdentityRequired)?;
            d.decrypt(std::iter::once(identity as &dyn age::Identity))
                .context("Failed to decrypt data (wrong key?)")?
        }
        age::Decryptor::Passphrase(d) => {
            let passphrase = passphrase.ok_or(PassphraseRequired)?;
            d.decrypt(passphrase, None)
                .context("Failed to decrypt data (wrong passphrase?)")?
        }
    };

    let mut reader = decryptor;
    let bytes_read = std::io::copy(&mut reader, &mut output).context("Failed to decrypt stream")?;

    Ok(bytes_read)
}

pub fn recipient_hint(recipient: &str) -> String {
    if recipient.len() > 12 {
        format!(
            "{}...{}",
            &recipient[..6],
            &recipient[recipient.len() - 4..]
        )
    } else {
        recipient.to_string()
    }
}

pub fn save_identity(identity: &age::x25519::Identity, path: &Path) -> Result<()> {
    use age::secrecy::ExposeSecret;

    let parent = path.parent();
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
    }

    let identity_secret = identity.to_string();
    let identity_str = identity_secret.expose_secret();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to open identity file: {}", path.display()))?;
        file.write_all(identity_str.as_bytes())
            .with_context(|| format!("Failed to write identity file: {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, identity_str.as_bytes())
            .with_context(|| format!("Failed to write identity file: {}", path.display()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("Failed to set permissions on: {}", path.display()))?;
    }

    Ok(())
}

pub fn prompt_optional_passphrase(prompt: &str) -> Result<Option<SecretString>> {
    let passphrase = rpassword::prompt_password(prompt).context("Failed to read passphrase")?;
    if passphrase.is_empty() {
        return Ok(None);
    }
    Ok(Some(SecretString::new(passphrase)))
}

pub fn load_identity_for_decryption(
    explicit_identity: Option<&String>,
) -> Result<Option<age::x25519::Identity>> {
    if let Some(path) = explicit_identity {
        let path = PathBuf::from(path);
        if !path.exists() {
            anyhow::bail!("Identity file not found at {}", path.display());
        }
        return Ok(Some(load_identity(&path).with_context(|| {
            format!("Failed to load identity from {}", path.display())
        })?));
    }

    if let Ok(config) = crate::config::Config::load() {
        if let Some(ref identity_path) = config.default_age_identity {
            let path = PathBuf::from(identity_path);
            if path.exists() {
                return Ok(Some(load_identity(&path).with_context(|| {
                    format!("Failed to load identity from {}", path.display())
                })?));
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let path = home.join(".boringcache").join("age-identity.txt");
        if path.exists() {
            return Ok(Some(load_identity(&path).with_context(|| {
                format!("Failed to load identity from {}", path.display())
            })?));
        }
    }

    Ok(None)
}

pub fn is_age_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(AGE_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (identity, recipient) = generate_keypair();
        let original = b"Hello, World! This is a test message.";

        let encrypted = encrypt_data(original, &recipient).unwrap();
        assert_ne!(encrypted, original.to_vec());

        let decrypted = decrypt_data(&encrypted, &identity).unwrap();
        assert_eq!(decrypted, original.to_vec());
    }

    #[test]
    fn test_recipient_hint() {
        let full = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        let hint = recipient_hint(full);
        assert_eq!(hint, "age1ql...ac8p");
    }

    #[test]
    fn test_encrypt_stream_roundtrip() {
        let (identity, recipient) = generate_keypair();
        let original = b"Stream encryption test data that is a bit longer to test streaming.";

        let mut encrypted = Vec::new();
        encrypt_stream(original.as_slice(), &mut encrypted, &recipient).unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(encrypted.as_slice(), &mut decrypted, Some(&identity), None).unwrap();

        assert_eq!(decrypted, original.to_vec());
    }
}

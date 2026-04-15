use age::secrecy::SecretString;
use anyhow::{Context, Result};
use std::io::{Cursor, Read, Write};

use super::errors::{IdentityRequired, PassphraseRequired};

const AGE_MAGIC: &[u8] = b"age-encryption.org/";

pub fn encrypt_data(data: &[u8], recipient: &age::x25519::Recipient) -> Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .context("Failed to create encryptor")?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("Failed to initialize encryption")?;

    writer.write_all(data).context("Failed to encrypt data")?;
    writer.finish().context("Failed to finalize encryption")?;

    Ok(encrypted)
}

pub fn decrypt_data(encrypted: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let decryptor = age::Decryptor::new(encrypted).context("Failed to parse encrypted data")?;

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
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .context("Failed to create encryptor")?;

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
    let decryptor = age::Decryptor::new(input).context("Failed to parse encrypted data")?;

    let mut reader = if decryptor.is_scrypt() {
        let passphrase = passphrase.ok_or(PassphraseRequired)?;
        decryptor
            .decrypt(std::iter::once(
                &age::scrypt::Identity::new(passphrase.clone()) as &dyn age::Identity,
            ))
            .context("Failed to decrypt data (wrong passphrase?)")?
    } else {
        let identity = identity.ok_or(IdentityRequired)?;
        decryptor
            .decrypt(std::iter::once(identity as &dyn age::Identity))
            .context("Failed to decrypt data (wrong key?)")?
    };
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

pub fn is_age_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(AGE_MAGIC)
}

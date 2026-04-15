mod crypto;
mod errors;
mod identity;
mod passphrase;

#[cfg(test)]
mod tests;

pub use crypto::{
    decrypt_bytes, decrypt_data, decrypt_stream, encrypt_data, encrypt_stream, is_age_encrypted,
    recipient_hint,
};
pub use errors::{IdentityRequired, PassphraseRequired, is_passphrase_required};
pub use identity::{
    generate_keypair, identity_to_recipient, load_identity, load_identity_for_decryption,
    parse_recipient, save_identity,
};
pub use passphrase::{
    PassphraseCache, cached_passphrase, get_or_prompt_passphrase, prompt_optional_passphrase,
};

pub const ENCRYPTION_ALGORITHM_AGE_X25519: &str = "age-x25519";
pub const ENCRYPTION_ALGORITHM_AGE_SCRYPT: &str = "age-scrypt";

#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub recipient: String,
    pub identity_path: Option<String>,
}

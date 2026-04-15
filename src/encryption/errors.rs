#[derive(Debug, thiserror::Error)]
#[error("Encrypted data requires an identity file; use --identity or configure a default")]
pub struct IdentityRequired;

#[derive(Debug, thiserror::Error)]
#[error("Encrypted data requires a passphrase")]
pub struct PassphraseRequired;

pub fn is_passphrase_required(err: &anyhow::Error) -> bool {
    err.downcast_ref::<PassphraseRequired>().is_some()
}

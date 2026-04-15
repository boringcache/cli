use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

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

pub fn save_identity(identity: &age::x25519::Identity, path: &Path) -> Result<()> {
    use age::secrecy::ExposeSecret;

    if let Some(dir) = path.parent() {
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
        use std::io::Write;
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

pub fn load_identity_for_decryption(
    explicit_identity: Option<&String>,
) -> Result<Option<age::x25519::Identity>> {
    if let Some(path) = explicit_identity {
        let path = PathBuf::from(path);
        if !path.exists() {
            anyhow::bail!("Identity file not found at {}", path.display());
        }
        return Ok(Some(load_configured_identity(&path)?));
    }

    if let Ok(config) = crate::config::Config::load()
        && let Some(ref identity_path) = config.default_age_identity
    {
        let path = PathBuf::from(identity_path);
        if path.exists() {
            return Ok(Some(load_configured_identity(&path)?));
        }
    }

    if let Some(path) = default_identity_path()
        && path.exists()
    {
        return Ok(Some(load_configured_identity(&path)?));
    }

    Ok(None)
}

fn load_configured_identity(path: &Path) -> Result<age::x25519::Identity> {
    load_identity(path).with_context(|| format!("Failed to load identity from {}", path.display()))
}

fn default_identity_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".boringcache").join("age-identity.txt"))
}

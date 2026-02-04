use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::config::Config;
use crate::{encryption, ui};

pub async fn execute(workspace: Option<String>, identity_output: Option<String>) -> Result<()> {
    let workspace = match workspace {
        Some(ws) => ws,
        None => {
            let config = Config::load().context(
                "No workspace specified and no default workspace configured. \
                 Use: boringcache setup-encryption <workspace>",
            )?;
            config.get_default_workspace().map_err(|_| {
                anyhow::anyhow!(
                    "No workspace specified and no default workspace configured. \
                     Use: boringcache setup-encryption <workspace>"
                )
            })?
        }
    };

    let identity_path = match identity_output {
        Some(p) => PathBuf::from(p),
        None => get_default_age_identity_path()?,
    };

    let recipient = if identity_path.exists() {
        ui::info(&format!(
            "Using existing identity file: {}",
            identity_path.display()
        ));
        let identity = encryption::load_identity(&identity_path)?;
        encryption::identity_to_recipient(&identity)?
    } else {
        ui::info("Generating new Age encryption keypair...");
        let (identity, recipient) = encryption::generate_keypair();
        encryption::save_identity(&identity, &identity_path)?;
        ui::info(&format!(
            "Identity file saved to: {}",
            identity_path.display()
        ));
        recipient
    };

    let recipient_str = recipient.to_string();

    let mut config = Config::load().context("Failed to load config")?;
    config.default_age_identity = Some(identity_path.to_string_lossy().to_string());
    config.set_workspace_encryption(&workspace, &recipient_str);
    config.save_config()?;

    ui::info("");
    ui::info(&format!("Encryption enabled for workspace: {}", workspace));
    ui::info(&format!("Public key (recipient): {}", recipient_str));
    ui::info("");
    ui::info("From now on, save, restore, and mount commands for this workspace will");
    ui::info("automatically encrypt and decrypt data.");
    ui::info("");
    ui::info("To encrypt other workspaces:");
    ui::info("  boringcache setup-encryption <other-workspace>");

    Ok(())
}

fn get_default_age_identity_path() -> Result<PathBuf> {
    let config_dir = dirs::home_dir()
        .context("Could not find home directory")?
        .join(".boringcache");
    Ok(config_dir.join("age-identity.txt"))
}

use age::secrecy::SecretString;
use anyhow::{Context, Result};
use std::io::IsTerminal;
use std::sync::{Arc, Mutex};

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

pub fn prompt_optional_passphrase(prompt: &str) -> Result<Option<SecretString>> {
    let passphrase = rpassword::prompt_password(prompt).context("Failed to read passphrase")?;
    if passphrase.is_empty() {
        return Ok(None);
    }
    Ok(Some(SecretString::from(passphrase)))
}

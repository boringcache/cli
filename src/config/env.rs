use std::fs;

use super::{AuthPurpose, ValueSource};

pub(super) const DOCKER_SECRET_PATH: &str = "/run/secrets/bc_token";

pub fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub fn env_bool(key: &str) -> bool {
    env_var(key)
        .map(|raw| {
            let value = raw.trim();
            value == "1"
                || value.eq_ignore_ascii_case("true")
                || value.eq_ignore_ascii_case("yes")
                || value.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

pub(super) fn token_from_file() -> Option<String> {
    let token_file = env_var("BORINGCACHE_TOKEN_FILE").or_else(|| {
        let path = std::path::Path::new(DOCKER_SECRET_PATH);
        path.exists().then(|| DOCKER_SECRET_PATH.to_string())
    })?;
    let token = fs::read_to_string(token_file).ok()?;
    let token = token.trim().to_string();

    if token.is_empty() { None } else { Some(token) }
}

pub(super) fn token_file_source_path() -> Option<String> {
    let token_file = env_var("BORINGCACHE_TOKEN_FILE").or_else(|| {
        let path = std::path::Path::new(DOCKER_SECRET_PATH);
        path.exists().then(|| DOCKER_SECRET_PATH.to_string())
    })?;
    let token = fs::read_to_string(&token_file).ok()?;
    (!token.trim().is_empty()).then_some(token_file)
}

pub(super) fn env_api_token_for(purpose: AuthPurpose) -> Option<String> {
    match purpose {
        AuthPurpose::Default | AuthPurpose::Admin => {
            env_var("BORINGCACHE_ADMIN_TOKEN").or_else(|| env_var("BORINGCACHE_API_TOKEN"))
        }
        AuthPurpose::Restore => env_var("BORINGCACHE_RESTORE_TOKEN")
            .or_else(|| env_var("BORINGCACHE_SAVE_TOKEN"))
            .or_else(|| env_var("BORINGCACHE_ADMIN_TOKEN"))
            .or_else(|| env_var("BORINGCACHE_API_TOKEN")),
        AuthPurpose::Save => env_var("BORINGCACHE_SAVE_TOKEN")
            .or_else(|| env_var("BORINGCACHE_ADMIN_TOKEN"))
            .or_else(|| env_var("BORINGCACHE_API_TOKEN")),
    }
}

pub(super) fn purpose_missing_token_message(purpose: AuthPurpose) -> String {
    match purpose {
        AuthPurpose::Default | AuthPurpose::Restore => {
            "No authentication token configured. Set BORINGCACHE_RESTORE_TOKEN, \
             BORINGCACHE_SAVE_TOKEN, BORINGCACHE_ADMIN_TOKEN, BORINGCACHE_API_TOKEN, \
             BORINGCACHE_TOKEN_FILE, \
             or run 'boringcache auth --token <token>'."
                .to_string()
        }
        AuthPurpose::Save => {
            if env_var("BORINGCACHE_RESTORE_TOKEN").is_some() {
                "This command needs a save-capable token. BORINGCACHE_RESTORE_TOKEN is configured, \
                 but save requires BORINGCACHE_SAVE_TOKEN, BORINGCACHE_ADMIN_TOKEN, \
                 BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or a token saved with \
                 'boringcache auth --token <token>'."
                    .to_string()
            } else {
                "No save-capable token configured. Set BORINGCACHE_SAVE_TOKEN, \
                 BORINGCACHE_ADMIN_TOKEN, BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or run \
                 'boringcache auth --token <token>'."
                    .to_string()
            }
        }
        AuthPurpose::Admin => {
            if env_var("BORINGCACHE_SAVE_TOKEN").is_some()
                || env_var("BORINGCACHE_RESTORE_TOKEN").is_some()
            {
                "This command needs an admin-capable token. BORINGCACHE_RESTORE_TOKEN and \
                 BORINGCACHE_SAVE_TOKEN are not enough for admin operations. Use \
                 BORINGCACHE_ADMIN_TOKEN, BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or \
                 a token saved with 'boringcache auth --token <token>'."
                    .to_string()
            } else {
                "No admin-capable token configured. Use BORINGCACHE_ADMIN_TOKEN, \
                 BORINGCACHE_API_TOKEN, BORINGCACHE_TOKEN_FILE, or run \
                 'boringcache auth --token <token>'."
                    .to_string()
            }
        }
    }
}

pub(super) fn env_token_source_for(purpose: AuthPurpose) -> Option<ValueSource> {
    let keys = match purpose {
        AuthPurpose::Default | AuthPurpose::Admin => {
            &["BORINGCACHE_ADMIN_TOKEN", "BORINGCACHE_API_TOKEN"][..]
        }
        AuthPurpose::Restore => &[
            "BORINGCACHE_RESTORE_TOKEN",
            "BORINGCACHE_SAVE_TOKEN",
            "BORINGCACHE_ADMIN_TOKEN",
            "BORINGCACHE_API_TOKEN",
        ][..],
        AuthPurpose::Save => &[
            "BORINGCACHE_SAVE_TOKEN",
            "BORINGCACHE_ADMIN_TOKEN",
            "BORINGCACHE_API_TOKEN",
        ][..],
    };

    keys.iter()
        .find(|key| env_var(key).is_some())
        .map(|key| ValueSource::env(key))
}

use super::env::{env_token_source_for, token_file_source_path};
use super::{AuthPurpose, Config, ValueSource, env_var};

pub fn token_source_for(purpose: AuthPurpose) -> ValueSource {
    if let Some(source) = env_token_source_for(purpose) {
        return source;
    }

    if let Some(path) = token_file_source_path() {
        return ValueSource::token_file(path);
    }

    if let (Ok(config), Ok(path)) = (Config::load_from_file(), Config::config_path())
        && !config.token.trim().is_empty()
    {
        return ValueSource::config_file(path.display().to_string());
    }

    ValueSource::missing()
}

pub fn api_url_source() -> ValueSource {
    if env_var("BORINGCACHE_API_URL").is_some() {
        return ValueSource::env("BORINGCACHE_API_URL");
    }

    if let Ok(path) = Config::config_path()
        && path.exists()
    {
        return ValueSource::config_file(path.display().to_string());
    }

    ValueSource::default()
}

pub fn default_workspace_source() -> ValueSource {
    if env_var("BORINGCACHE_DEFAULT_WORKSPACE").is_some() {
        return ValueSource::env("BORINGCACHE_DEFAULT_WORKSPACE");
    }

    if let (Ok(config), Ok(path)) = (Config::load_from_file(), Config::config_path())
        && config
            .default_workspace
            .as_deref()
            .is_some_and(|workspace| !workspace.trim().is_empty())
    {
        return ValueSource::config_file(path.display().to_string());
    }

    ValueSource::missing()
}

use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub(super) enum DefaultPathKind {
    Relative(&'static str),
    Home(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct BuiltInEntrySpec {
    pub(super) default_tag: &'static str,
    pub(super) env_lookup: &'static [&'static str],
    pub(super) env_export: &'static [&'static str],
    pub(super) extra_env: &'static [(&'static str, &'static str)],
    pub(super) default_path: DefaultPathKind,
}

pub(super) fn builtin_entry(entry_id: &str) -> Option<BuiltInEntrySpec> {
    let empty_env: &[&str] = &[];
    let empty_pairs: &[(&str, &str)] = &[];

    match canonical_entry_id(entry_id).as_str() {
        "bundler" => Some(BuiltInEntrySpec {
            default_tag: "bundler",
            env_lookup: &["BUNDLE_PATH"],
            env_export: &["BUNDLE_PATH"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("vendor/bundle"),
        }),
        "bootsnap" => Some(BuiltInEntrySpec {
            default_tag: "bootsnap",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("tmp/cache/bootsnap"),
        }),
        "mise" => Some(BuiltInEntrySpec {
            default_tag: "mise-installs",
            env_lookup: &["MISE_INSTALLS_DIR"],
            env_export: &["MISE_INSTALLS_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Home(".local/share/mise/installs"),
        }),
        "node_modules" => Some(BuiltInEntrySpec {
            default_tag: "node_modules",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("node_modules"),
        }),
        "pnpm-store" => Some(BuiltInEntrySpec {
            default_tag: "pnpm-store",
            env_lookup: &["PNPM_STORE_DIR", "NPM_CONFIG_STORE_DIR"],
            env_export: &["PNPM_STORE_DIR", "NPM_CONFIG_STORE_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".pnpm-store"),
        }),
        "yarn-cache" => Some(BuiltInEntrySpec {
            default_tag: "yarn-cache",
            env_lookup: &["YARN_CACHE_FOLDER"],
            env_export: &["YARN_CACHE_FOLDER"],
            extra_env: &[("YARN_ENABLE_GLOBAL_CACHE", "false")],
            default_path: DefaultPathKind::Relative(".yarn-cache"),
        }),
        "npm-cache" => Some(BuiltInEntrySpec {
            default_tag: "npm-cache",
            env_lookup: &["npm_config_cache", "NPM_CONFIG_CACHE"],
            env_export: &["npm_config_cache", "NPM_CONFIG_CACHE"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".npm-cache"),
        }),
        "uv-cache" => Some(BuiltInEntrySpec {
            default_tag: "uv-cache",
            env_lookup: &["UV_CACHE_DIR"],
            env_export: &["UV_CACHE_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".uv-cache"),
        }),
        "go-mod-cache" => Some(BuiltInEntrySpec {
            default_tag: "go-mod-cache",
            env_lookup: &["GOMODCACHE"],
            env_export: &["GOMODCACHE"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".go/pkg/mod"),
        }),
        "go-build-cache" => Some(BuiltInEntrySpec {
            default_tag: "go-build-cache",
            env_lookup: &["GOCACHE"],
            env_export: &["GOCACHE"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".go/build-cache"),
        }),
        "composer-cache" => Some(BuiltInEntrySpec {
            default_tag: "composer-cache",
            env_lookup: &["COMPOSER_CACHE_DIR"],
            env_export: &["COMPOSER_CACHE_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative(".composer-cache"),
        }),
        "cargo-registry" => Some(BuiltInEntrySpec {
            default_tag: "cargo-registry",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Home(".cargo/registry"),
        }),
        "cargo-git" => Some(BuiltInEntrySpec {
            default_tag: "cargo-git",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Home(".cargo/git"),
        }),
        "cargo-bin" => Some(BuiltInEntrySpec {
            default_tag: "cargo-bin",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Home(".cargo/bin"),
        }),
        "target" => Some(BuiltInEntrySpec {
            default_tag: "target",
            env_lookup: empty_env,
            env_export: empty_env,
            extra_env: &[("CARGO_INCREMENTAL", "0")],
            default_path: DefaultPathKind::Relative("target"),
        }),
        "sccache-dir" => Some(BuiltInEntrySpec {
            default_tag: "sccache",
            env_lookup: &["SCCACHE_DIR"],
            env_export: &["SCCACHE_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Home(".cache/sccache"),
        }),
        "vendor" => Some(BuiltInEntrySpec {
            default_tag: "vendor",
            env_lookup: &["COMPOSER_VENDOR_DIR"],
            env_export: &["COMPOSER_VENDOR_DIR"],
            extra_env: empty_pairs,
            default_path: DefaultPathKind::Relative("vendor"),
        }),
        _ => None,
    }
}

pub fn infer_entries_from_command(command: &[String]) -> Vec<String> {
    let Some(binary) = command.first() else {
        return Vec::new();
    };
    let command_name = Path::new(binary)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(binary.as_str())
        .to_ascii_lowercase();
    let subcommand = command
        .get(1)
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    match (command_name.as_str(), subcommand.as_str()) {
        ("bundle", "install") => vec!["bundler".to_string()],
        ("mise", "install") => vec!["mise".to_string()],
        ("npm", "install") | ("npm", "ci") => {
            vec!["npm-cache".to_string(), "node_modules".to_string()]
        }
        ("pnpm", "install") | ("pnpm", "i") => {
            vec!["pnpm-store".to_string(), "node_modules".to_string()]
        }
        ("yarn", "install") => vec!["yarn-cache".to_string(), "node_modules".to_string()],
        ("uv", "sync") | ("uv", "pip") => vec!["uv-cache".to_string()],
        _ => Vec::new(),
    }
}

pub fn normalize_profile_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

pub(super) fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

pub fn canonical_entry_id(value: &str) -> String {
    match normalize_key(value).as_str() {
        "mise-installs" => "mise".to_string(),
        "npm" => "npm-cache".to_string(),
        "pnpm" => "pnpm-store".to_string(),
        "uv" => "uv-cache".to_string(),
        "yarn" => "yarn-cache".to_string(),
        "node-modules" => "node_modules".to_string(),
        "go-mod" => "go-mod-cache".to_string(),
        "go-build" => "go-build-cache".to_string(),
        "sccache" => "sccache-dir".to_string(),
        "target-dir" => "target".to_string(),
        other => other.to_string(),
    }
}

pub fn built_in_default_tag(entry_id: &str) -> Option<&'static str> {
    builtin_entry(entry_id).map(|spec| spec.default_tag)
}

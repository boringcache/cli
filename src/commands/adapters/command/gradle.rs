use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{AdapterCommandOptions, AdapterRunner};
use crate::proxy;

pub(super) const GRADLE_CACHE_URL_ENV: &str = "BORINGCACHE_GRADLE_CACHE_URL";
pub(super) const GRADLE_CACHE_PUSH_ENV: &str = "BORINGCACHE_GRADLE_CACHE_PUSH";
pub(super) const GRADLE_INIT_SCRIPT_NAME: &str = "boringcache-gradle-build-cache.init.gradle";
pub(super) const GRADLE_INIT_SCRIPT: &str = r#"import org.gradle.caching.http.HttpBuildCache

gradle.settingsEvaluated { settings ->
    def cacheUrl = System.getenv("BORINGCACHE_GRADLE_CACHE_URL")
    if (cacheUrl) {
        settings.buildCache {
            remote(HttpBuildCache) {
                enabled = true
                url = uri(cacheUrl)
                push = System.getenv("BORINGCACHE_GRADLE_CACHE_PUSH") == "true"
                allowInsecureProtocol = true
            }
        }
    }
}
"#;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "gradle",
    inject_proxy_env,
    prepare_command,
};

fn inject_proxy_env(
    set: &mut BTreeMap<String, String>,
    context: &proxy::ProxyContext,
    options: &AdapterCommandOptions,
) {
    set.insert(
        GRADLE_CACHE_URL_ENV.to_string(),
        format!("{}/cache/", context.endpoint()),
    );
    set.insert(
        GRADLE_CACHE_PUSH_ENV.to_string(),
        (!options.read_only).to_string(),
    );
}

fn prepare_command(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    _: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    let Some(_) = proxy_context else {
        return Ok(command.to_vec());
    };

    let init_script = ensure_gradle_init_script()?;
    let init_script_arg = format!("--init-script={}", init_script.display());
    let mut injected = Vec::new();
    if !command
        .iter()
        .any(|arg| arg == "--build-cache" || arg == "--no-build-cache")
    {
        injected.push("--build-cache".to_string());
    }
    if !command_has_exact_init_script(command, &init_script) {
        injected.push(init_script_arg);
    }
    if injected.is_empty() {
        return Ok(command.to_vec());
    }

    let mut prepared = Vec::with_capacity(command.len() + injected.len());
    if let Some(program) = command.first() {
        prepared.push(program.clone());
        prepared.extend(injected);
        prepared.extend(command.iter().skip(1).cloned());
        Ok(prepared)
    } else {
        Ok(command.to_vec())
    }
}

fn ensure_gradle_init_script() -> Result<PathBuf> {
    let path = std::env::temp_dir().join(GRADLE_INIT_SCRIPT_NAME);
    let existing = std::fs::read_to_string(&path).ok();
    if existing.as_deref() == Some(GRADLE_INIT_SCRIPT) {
        return Ok(path);
    }
    std::fs::write(&path, GRADLE_INIT_SCRIPT)
        .with_context(|| format!("Failed to write Gradle init script {}", path.display()))?;
    Ok(path)
}

fn command_has_exact_init_script(command: &[String], script_path: &Path) -> bool {
    let expected = script_path.to_string_lossy();
    let mut iter = command.iter();
    while let Some(arg) = iter.next() {
        if arg == "-I" || arg == "--init-script" {
            if let Some(value) = iter.next()
                && value == expected.as_ref()
            {
                return true;
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--init-script=")
            && value == expected.as_ref()
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> proxy::ProxyContext {
        proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        }
    }

    fn options(read_only: bool) -> AdapterCommandOptions {
        AdapterCommandOptions {
            cache_ref_tag: "buildcache".to_string(),
            cache_mode: "max".to_string(),
            read_only,
            docker_oci_cache: None,
            sccache_key_prefix: None,
        }
    }

    #[test]
    fn gradle_env_plan_sets_cache_url_and_push_mode() {
        let mut env = BTreeMap::new();
        inject_proxy_env(&mut env, &context(), &options(false));
        assert_eq!(
            env.get(GRADLE_CACHE_URL_ENV),
            Some(&"http://127.0.0.1:5000/cache/".to_string())
        );
        assert_eq!(env.get(GRADLE_CACHE_PUSH_ENV), Some(&"true".to_string()));

        let mut read_only_env = BTreeMap::new();
        inject_proxy_env(&mut read_only_env, &context(), &options(true));
        assert_eq!(
            read_only_env.get(GRADLE_CACHE_PUSH_ENV),
            Some(&"false".to_string())
        );
    }

    #[test]
    fn gradle_prepare_command_injects_init_script_and_build_cache() {
        let command = prepare_command(
            &[
                "./gradlew".to_string(),
                "build".to_string(),
                "--no-daemon".to_string(),
            ],
            Some(&context()),
            &options(false),
        )
        .unwrap();

        assert_eq!(command[0], "./gradlew");
        assert_eq!(command[1], "--build-cache");
        assert!(command[2].starts_with("--init-script="));
        assert_eq!(command[3], "build");
    }

    #[test]
    fn gradle_prepare_command_keeps_existing_build_cache_disable_flag() {
        let command = prepare_command(
            &[
                "./gradlew".to_string(),
                "--no-build-cache".to_string(),
                "build".to_string(),
            ],
            Some(&context()),
            &options(false),
        )
        .unwrap();

        assert!(!command.iter().any(|arg| arg == "--build-cache"));
    }
}

use anyhow::Result;

use super::{AdapterCommandOptions, AdapterRunner};
use crate::proxy;

const MAVEN_CACHE_ENABLED_PROPERTY: &str = "maven.build.cache.enabled";
const MAVEN_REMOTE_ENABLED_PROPERTY: &str = "maven.build.cache.remote.enabled";
const MAVEN_REMOTE_URL_PROPERTY: &str = "maven.build.cache.remote.url";
const MAVEN_REMOTE_SAVE_PROPERTY: &str = "maven.build.cache.remote.save.enabled";

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "maven",
    inject_proxy_env: super::no_extra_proxy_env,
    prepare_command,
};

fn prepare_command(
    command: &[String],
    proxy_context: Option<&proxy::ProxyContext>,
    options: &AdapterCommandOptions,
) -> Result<Vec<String>> {
    let Some(context) = proxy_context else {
        return Ok(command.to_vec());
    };

    let mut injected = Vec::new();
    if !has_system_property(command, MAVEN_CACHE_ENABLED_PROPERTY) {
        injected.push(format!("-D{MAVEN_CACHE_ENABLED_PROPERTY}=true"));
    }
    if !has_system_property(command, MAVEN_REMOTE_ENABLED_PROPERTY) {
        injected.push(format!("-D{MAVEN_REMOTE_ENABLED_PROPERTY}=true"));
    }
    if !has_system_property(command, MAVEN_REMOTE_URL_PROPERTY) {
        injected.push(format!(
            "-D{MAVEN_REMOTE_URL_PROPERTY}={}",
            context.endpoint()
        ));
    }
    if !has_system_property(command, MAVEN_REMOTE_SAVE_PROPERTY) {
        injected.push(format!(
            "-D{MAVEN_REMOTE_SAVE_PROPERTY}={}",
            !options.read_only
        ));
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

fn has_system_property(command: &[String], property: &str) -> bool {
    let exact = format!("-D{property}");
    let prefix = format!("-D{property}=");
    command
        .iter()
        .any(|arg| arg == &exact || arg.starts_with(&prefix))
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
            gradle_home: None,
            node_package_manager_env: Default::default(),
        }
    }

    #[test]
    fn maven_prepare_command_injects_remote_cache_properties() {
        let command = prepare_command(
            &[
                "mvn".to_string(),
                "install".to_string(),
                "-DskipTests".to_string(),
            ],
            Some(&context()),
            &options(false),
        )
        .unwrap();

        assert_eq!(command[0], "mvn");
        assert!(
            command[1..]
                .iter()
                .any(|arg| arg == "-Dmaven.build.cache.enabled=true")
        );
        assert!(
            command[1..]
                .iter()
                .any(|arg| arg == "-Dmaven.build.cache.remote.enabled=true")
        );
        assert!(
            command[1..]
                .iter()
                .any(|arg| arg == "-Dmaven.build.cache.remote.url=http://127.0.0.1:5000")
        );
        assert!(
            command[1..]
                .iter()
                .any(|arg| arg == "-Dmaven.build.cache.remote.save.enabled=true")
        );
    }

    #[test]
    fn maven_prepare_command_preserves_explicit_properties() {
        let command = prepare_command(
            &[
                "mvn".to_string(),
                "-Dmaven.build.cache.remote.url=http://cache.example".to_string(),
                "-Dmaven.build.cache.remote.save.enabled=false".to_string(),
                "install".to_string(),
            ],
            Some(&context()),
            &options(false),
        )
        .unwrap();

        assert_eq!(
            command,
            vec![
                "mvn".to_string(),
                "-Dmaven.build.cache.enabled=true".to_string(),
                "-Dmaven.build.cache.remote.enabled=true".to_string(),
                "-Dmaven.build.cache.remote.url=http://cache.example".to_string(),
                "-Dmaven.build.cache.remote.save.enabled=false".to_string(),
                "install".to_string(),
            ]
        );
    }

    #[test]
    fn maven_prepare_command_uses_read_only_save_setting() {
        let command = prepare_command(
            &["mvn".to_string(), "verify".to_string()],
            Some(&context()),
            &options(true),
        )
        .unwrap();

        assert!(
            command[1..]
                .iter()
                .any(|arg| arg == "-Dmaven.build.cache.remote.save.enabled=false")
        );
    }
}

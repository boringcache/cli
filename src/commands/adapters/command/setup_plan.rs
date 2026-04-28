use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{AdapterCommandOptions, AdapterKind};
use crate::cli::AdapterArgs;
use crate::proxy;

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct AdapterSetupPlan {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) env_vars: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) files: Vec<AdapterSetupFile>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) directories: Vec<String>,
}

impl AdapterSetupPlan {
    pub(super) fn is_empty(&self) -> bool {
        self.env_vars.is_empty() && self.files.is_empty() && self.directories.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct AdapterSetupFile {
    pub(super) path: String,
    pub(super) mode: AdapterSetupFileMode,
    pub(super) content: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum AdapterSetupFileMode {
    Write,
    Append,
}

pub(super) fn adapter_setup_plan(
    kind: AdapterKind,
    args: &AdapterArgs,
    current_dir: &Path,
    context: &proxy::ProxyContext,
    options: &AdapterCommandOptions,
) -> Result<AdapterSetupPlan> {
    match kind {
        AdapterKind::Bazel => bazel_setup_plan(args, context, options),
        AdapterKind::Gradle => gradle_setup_plan(args, current_dir, context, options),
        AdapterKind::Maven => maven_setup_plan(args, current_dir, context, options),
        _ => Ok(AdapterSetupPlan::default()),
    }
}

fn bazel_setup_plan(
    args: &AdapterArgs,
    context: &proxy::ProxyContext,
    options: &AdapterCommandOptions,
) -> Result<AdapterSetupPlan> {
    let remote_max_connections = std::env::var("BORINGCACHE_BAZEL_REMOTE_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(64);
    let extra_lines = args
        .bazelrc_line
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut config_lines = vec![
        String::new(),
        "# BoringCache remote cache".to_string(),
        format!("build --remote_cache={}", context.endpoint()),
        format!("build --remote_upload_local_results={}", !options.read_only),
        "build --remote_cache_async=false".to_string(),
        "build --remote_download_minimal".to_string(),
        format!("build --remote_max_connections={remote_max_connections}"),
    ];
    config_lines.extend(extra_lines.into_iter().map(ToOwned::to_owned));
    config_lines.push(String::new());

    Ok(AdapterSetupPlan {
        files: vec![AdapterSetupFile {
            path: home_path(".bazelrc")?,
            mode: AdapterSetupFileMode::Append,
            content: config_lines.join("\n"),
        }],
        ..AdapterSetupPlan::default()
    })
}

fn gradle_setup_plan(
    args: &AdapterArgs,
    current_dir: &Path,
    context: &proxy::ProxyContext,
    options: &AdapterCommandOptions,
) -> Result<AdapterSetupPlan> {
    let gradle_home = resolve_user_path(
        args.gradle_home.as_deref().unwrap_or("~/.gradle"),
        current_dir,
    )?;
    let init_script = gradle_home
        .join("init.d")
        .join(super::gradle::GRADLE_INIT_SCRIPT_NAME);
    let mut files = vec![AdapterSetupFile {
        path: path_string(init_script),
        mode: AdapterSetupFileMode::Write,
        content: super::gradle::GRADLE_INIT_SCRIPT.to_string(),
    }];
    if !args.no_gradle_build_cache_property {
        files.push(AdapterSetupFile {
            path: path_string(gradle_home.join("gradle.properties")),
            mode: AdapterSetupFileMode::Append,
            content: "\norg.gradle.caching=true\n".to_string(),
        });
    }

    let mut env_vars = BTreeMap::new();
    AdapterKind::Gradle
        .proxy_env_plan(context, options)
        .set
        .into_iter()
        .for_each(|(key, value)| {
            env_vars.insert(key, value);
        });

    Ok(AdapterSetupPlan {
        env_vars,
        files,
        ..AdapterSetupPlan::default()
    })
}

fn maven_setup_plan(
    args: &AdapterArgs,
    current_dir: &Path,
    context: &proxy::ProxyContext,
    options: &AdapterCommandOptions,
) -> Result<AdapterSetupPlan> {
    let extensions_path = resolve_user_path(
        args.maven_extensions_path
            .as_deref()
            .unwrap_or(".mvn/extensions.xml"),
        current_dir,
    )?;
    let build_cache_config_path = resolve_user_path(
        args.maven_build_cache_config_path
            .as_deref()
            .unwrap_or(".mvn/maven-build-cache-config.xml"),
        current_dir,
    )?;
    let local_repo = resolve_user_path(
        args.maven_local_repo
            .as_deref()
            .unwrap_or("~/.m2/repository"),
        current_dir,
    )?;
    let extension_version = args
        .maven_build_cache_extension_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("1.2.2");
    let cache_id = args
        .maven_build_cache_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("boringcache");

    Ok(AdapterSetupPlan {
        files: vec![
            AdapterSetupFile {
                path: path_string(extensions_path.clone()),
                mode: AdapterSetupFileMode::Write,
                content: maven_extensions_content(&extensions_path, extension_version)?,
            },
            AdapterSetupFile {
                path: path_string(build_cache_config_path),
                mode: AdapterSetupFileMode::Write,
                content: maven_build_cache_config(context, options.read_only, cache_id),
            },
        ],
        directories: vec![path_string(local_repo)],
        ..AdapterSetupPlan::default()
    })
}

fn home_path(relative: &str) -> Result<String> {
    let home = dirs::home_dir().context("Failed to determine home directory")?;
    Ok(path_string(home.join(relative)))
}

fn resolve_user_path(value: &str, current_dir: &Path) -> Result<PathBuf> {
    let expanded = crate::command_support::expand_tilde_path(value);
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(current_dir.join(path))
    }
}

fn path_string(path: PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn maven_extension_block(version: &str) -> String {
    [
        "  <extension>",
        "    <groupId>org.apache.maven.extensions</groupId>",
        "    <artifactId>maven-build-cache-extension</artifactId>",
        &format!("    <version>{version}</version>"),
        "  </extension>",
    ]
    .join("\n")
}

fn maven_extensions_content(path: &Path, version: &str) -> Result<String> {
    let extension_block = maven_extension_block(version);
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing.contains("<artifactId>maven-build-cache-extension</artifactId>") {
            return Ok(existing);
        }
        if existing.contains("</extensions>") {
            return Ok(existing.replace(
                "</extensions>",
                &format!("{extension_block}\n</extensions>"),
            ));
        }
    }

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<extensions xmlns="http://maven.apache.org/EXTENSIONS/1.0.0"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="http://maven.apache.org/EXTENSIONS/1.0.0 https://maven.apache.org/xsd/core-extensions-1.0.0.xsd">
{extension_block}
</extensions>
"#
    ))
}

fn maven_build_cache_config(
    context: &proxy::ProxyContext,
    read_only: bool,
    cache_id: &str,
) -> String {
    let endpoint = context.endpoint();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<cache xmlns="http://maven.apache.org/BUILD-CACHE-CONFIG/1.2.0"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://maven.apache.org/BUILD-CACHE-CONFIG/1.2.0 https://maven.apache.org/xsd/build-cache-config-1.2.0.xsd">
  <configuration>
    <remote enabled="true" saveToRemote="{}" transport="resolver" id="{cache_id}">
      <url>{endpoint}</url>
    </remote>
  </configuration>
</cache>
"#,
        !read_only
    )
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

    fn adapter_args() -> AdapterArgs {
        AdapterArgs {
            workspace: None,
            tag: None,
            port: None,
            host: None,
            endpoint_host: None,
            no_platform: false,
            no_git: false,
            read_only: false,
            fail_on_cache_error: false,
            metadata_hint: Vec::new(),
            oci_prefetch_ref: Vec::new(),
            oci_hydration: "metadata-only".to_string(),
            on_demand: false,
            entry: Vec::new(),
            profile: Vec::new(),
            skip_restore: false,
            skip_save: false,
            save_on_failure: false,
            cache_mode: None,
            cache_ref_tag: None,
            cache_run_ref_tag: None,
            cache_from_ref_tag: Vec::new(),
            cache_promote_ref_tag: Vec::new(),
            bazelrc_line: Vec::new(),
            gradle_home: None,
            no_gradle_build_cache_property: false,
            maven_local_repo: None,
            maven_extensions_path: None,
            maven_build_cache_config_path: None,
            maven_build_cache_extension_version: None,
            maven_build_cache_id: None,
            dry_run: true,
            json: true,
            command: Vec::new(),
        }
    }

    #[test]
    fn maven_config_honors_read_only() {
        let config = maven_build_cache_config(&context(), true, "boringcache");
        assert!(config.contains("saveToRemote=\"false\""));
        assert!(config.contains("<url>http://127.0.0.1:5000</url>"));
    }

    #[test]
    fn maven_extensions_inserts_into_existing_extensions_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("extensions.xml");
        std::fs::write(&path, "<extensions>\n</extensions>\n").unwrap();

        let content = maven_extensions_content(&path, "1.2.2").unwrap();
        assert!(content.contains("<artifactId>maven-build-cache-extension</artifactId>"));
        assert!(content.contains("<version>1.2.2</version>"));
    }

    #[test]
    fn gradle_setup_uses_adapter_env_contract() {
        let args = adapter_args();
        let plan = gradle_setup_plan(&args, Path::new("."), &context(), &options(false)).unwrap();
        assert_eq!(
            plan.env_vars
                .get(super::super::gradle::GRADLE_CACHE_PUSH_ENV),
            Some(&"true".to_string())
        );
    }
}

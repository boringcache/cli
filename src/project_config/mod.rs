mod builtins;
mod discover;
mod model;
mod resolve;

pub use builtins::{
    built_in_default_tag, canonical_entry_id, infer_entries_from_command, normalize_profile_name,
};
pub use discover::discover;
pub use model::{
    AdapterCommandConfig, AdapterConfig, LoadedRepoConfig, RepoConfig, RepoEntryConfig,
    RepoProfileConfig, ResolvedAdapterConfig, ResolvedRunEntryPlan, ResolvedRunPlan,
    RunEntryRequestSource, RunEntryResolutionSource,
};
pub use resolve::{prefer_cli_list, prefer_cli_scalar, resolve_adapter_config, resolve_run_plan};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;
    use tempfile::TempDir;

    #[test]
    fn discovers_repo_config_from_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let project_dir = temp_dir.path().join("project");
        let nested_dir = project_dir.join("nested");
        std::fs::create_dir_all(&nested_dir).unwrap();
        std::fs::write(
            project_dir.join(".boringcache.toml"),
            r#"
workspace = "org/workspace"

[entries.bundler]
tag = "bundler-gems"
"#,
        )
        .unwrap();

        let loaded = discover(&nested_dir).unwrap().unwrap();
        assert_eq!(loaded.root, project_dir);
        assert_eq!(loaded.config.workspace.as_deref(), Some("org/workspace"));
    }

    #[test]
    fn ignores_bare_boringcache_toml() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join("boringcache.toml"),
            r#"
workspace = "org/workspace"
"#,
        )
        .unwrap();

        assert!(discover(temp_dir.path()).unwrap().is_none());
    }

    #[test]
    fn resolves_profile_entries_with_built_in_defaults() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"

[entries.bundler]
tag = "bundler-gems"

[profiles.bundle-install]
entries = ["bundler"]
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[String::from("bundle_install")],
            &[],
            &["bundle".to_string(), "install".to_string()],
        )
        .unwrap();

        assert_eq!(plan.workspace.as_deref(), Some("org/workspace"));
        assert_eq!(
            plan.tag_path_pairs,
            vec![format!(
                "bundler-gems:{}",
                temp_dir.path().join("vendor/bundle").display()
            )]
        );
        assert_eq!(
            plan.env_vars.get("BUNDLE_PATH"),
            Some(&temp_dir.path().join("vendor/bundle").display().to_string())
        );
    }

    #[test]
    fn infers_bundle_install_without_profile() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[],
            &["bundle".to_string(), "install".to_string()],
        )
        .unwrap();

        assert_eq!(plan.workspace.as_deref(), Some("org/workspace"));
        assert_eq!(
            plan.tag_path_pairs,
            vec![format!(
                "bundler:{}",
                temp_dir.path().join("vendor/bundle").display()
            )]
        );
    }

    #[test]
    fn uses_entry_default_path_override_before_built_in_default() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
[entries.mise]
default_path = "/mise/installs"
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[String::from("mise")],
            &["mise".to_string(), "install".to_string()],
        )
        .unwrap();

        assert_eq!(plan.tag_path_pairs, vec!["mise-installs:/mise/installs"]);
        assert_eq!(
            plan.env_vars.get("MISE_INSTALLS_DIR"),
            Some(&"/mise/installs".to_string())
        );
    }

    #[test]
    fn resolves_go_cache_built_ins_with_default_paths_and_env_exports() {
        let temp_dir = TempDir::new().unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[String::from("go-mod-cache"), String::from("go-build-cache")],
            &[],
        )
        .unwrap();

        assert_eq!(
            plan.tag_path_pairs,
            vec![
                format!(
                    "go-mod-cache:{}",
                    temp_dir.path().join(".go/pkg/mod").display()
                ),
                format!(
                    "go-build-cache:{}",
                    temp_dir.path().join(".go/build-cache").display()
                ),
            ]
        );
        assert_eq!(
            plan.env_vars.get("GOMODCACHE"),
            Some(&temp_dir.path().join(".go/pkg/mod").display().to_string())
        );
        assert_eq!(
            plan.env_vars.get("GOCACHE"),
            Some(
                &temp_dir
                    .path()
                    .join(".go/build-cache")
                    .display()
                    .to_string()
            )
        );
    }

    #[test]
    fn resolves_rust_cache_built_ins_with_default_paths_and_env_exports() {
        let _guard = test_env::lock();
        let temp_dir = TempDir::new().unwrap();
        let cargo_home = temp_dir.path().join("cargo-home");
        let sccache_dir = temp_dir.path().join("sccache-cache");

        test_env::set_var("CARGO_HOME", cargo_home.as_os_str());
        test_env::set_var("SCCACHE_DIR", sccache_dir.as_os_str());

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[
                String::from("cargo-registry"),
                String::from("cargo-git"),
                String::from("cargo-bin"),
                String::from("target"),
                String::from("sccache-dir"),
            ],
            &[],
        )
        .unwrap();

        assert_eq!(
            plan.tag_path_pairs,
            vec![
                format!("cargo-registry:{}", cargo_home.join("registry").display()),
                format!("cargo-git:{}", cargo_home.join("git").display()),
                format!("cargo-bin:{}", cargo_home.join("bin").display()),
                format!("target:{}", temp_dir.path().join("target").display()),
                format!("sccache:{}", sccache_dir.display()),
            ]
        );
        assert_eq!(
            plan.env_vars.get("SCCACHE_DIR"),
            Some(&sccache_dir.display().to_string())
        );
    }

    #[test]
    fn resolves_composer_cache_and_vendor_from_composer_json_config() {
        let _guard = test_env::lock();
        test_env::remove_var("COMPOSER_CACHE_DIR");
        test_env::remove_var("COMPOSER_VENDOR_DIR");

        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join("composer.json"),
            r#"
{
  "name": "demo/app",
  "config": {
    "cache-dir": "var/composer-cache",
    "vendor-dir": "deps/vendor"
  }
}
"#,
        )
        .unwrap();

        let plan = resolve_run_plan(
            temp_dir.path(),
            &[],
            &[String::from("composer-cache"), String::from("vendor")],
            &[],
        )
        .unwrap();

        assert_eq!(
            plan.tag_path_pairs,
            vec![
                format!(
                    "composer-cache:{}",
                    temp_dir.path().join("var/composer-cache").display()
                ),
                format!("vendor:{}", temp_dir.path().join("deps/vendor").display()),
            ]
        );
        assert_eq!(
            plan.env_vars.get("COMPOSER_CACHE_DIR"),
            Some(
                &temp_dir
                    .path()
                    .join("var/composer-cache")
                    .display()
                    .to_string()
            )
        );
        assert_eq!(
            plan.env_vars.get("COMPOSER_VENDOR_DIR"),
            Some(&temp_dir.path().join("deps/vendor").display().to_string())
        );
    }

    #[test]
    fn parses_adapter_config_with_command_array() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"

[adapters.turbo]
tag = "turbo-main"
command = ["pnpm", "turbo", "run", "build"]
entries = ["pnpm-store"]
profiles = ["bundle-install"]
metadata-hints = ["phase=warm"]
fail-on-cache-error = true
skip-save = true
save-on-failure = true
port = 5001
endpoint-host = "host.docker.internal"
sccache-key-prefix = "rust/ci"
"#,
        )
        .unwrap();

        let resolved = resolve_adapter_config(temp_dir.path(), "turbo").unwrap();
        let loaded = resolved.loaded_config.unwrap();
        let adapter = resolved.adapter_config.unwrap();

        assert_eq!(loaded.config.workspace.as_deref(), Some("org/workspace"));
        assert_eq!(adapter.tag.as_deref(), Some("turbo-main"));
        assert_eq!(adapter.entries, vec!["pnpm-store"]);
        assert_eq!(adapter.profiles, vec!["bundle-install"]);
        assert_eq!(adapter.metadata_hints, vec!["phase=warm"]);
        assert!(adapter.fail_on_cache_error);
        assert!(adapter.skip_save);
        assert!(adapter.save_on_failure);
        assert_eq!(adapter.port, Some(5001));
        assert_eq!(
            adapter.endpoint_host.as_deref(),
            Some("host.docker.internal")
        );
        assert_eq!(adapter.sccache_key_prefix.as_deref(), Some("rust/ci"));
        assert_eq!(
            adapter.command.unwrap().argv().unwrap(),
            vec!["pnpm", "turbo", "run", "build"]
        );
    }

    #[test]
    fn parses_adapter_command_string_with_shlex() {
        let command = AdapterCommandConfig::String(
            r#"sh -c 'pnpm install --frozen-lockfile && pnpm turbo run build'"#.to_string(),
        );

        assert_eq!(
            command.argv().unwrap(),
            vec![
                "sh",
                "-c",
                "pnpm install --frozen-lockfile && pnpm turbo run build"
            ]
        );
    }

    #[test]
    fn adapter_resolution_preserves_loaded_config_when_adapter_missing() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".boringcache.toml"),
            r#"
workspace = "org/workspace"
"#,
        )
        .unwrap();

        let resolved = resolve_adapter_config(temp_dir.path(), "turbo").unwrap();
        assert!(resolved.loaded_config.is_some());
        assert!(resolved.adapter_config.is_none());
    }

    #[test]
    fn prefer_cli_scalar_uses_cli_value_when_present() {
        assert_eq!(
            prefer_cli_scalar(Some("configured".to_string()), Some("cli".to_string())),
            Some("cli".to_string())
        );
        assert_eq!(
            prefer_cli_scalar(Some("configured".to_string()), None),
            Some("configured".to_string())
        );
    }

    #[test]
    fn prefer_cli_list_replaces_configured_values_when_cli_values_exist() {
        let configured = vec!["bundler".to_string(), "pnpm-store".to_string()];
        let cli = vec!["node-modules".to_string(), "bundler".to_string()];

        assert_eq!(
            prefer_cli_list(&configured, &cli, canonical_entry_id),
            vec!["node_modules".to_string(), "bundler".to_string()]
        );
        assert_eq!(
            prefer_cli_list(&configured, &[], canonical_entry_id),
            vec!["bundler".to_string(), "pnpm-store".to_string()]
        );
    }
}

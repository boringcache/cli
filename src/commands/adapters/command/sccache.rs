use std::collections::BTreeMap;
use std::process::Stdio;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;
use crate::ui;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "sccache",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(
    set: &mut BTreeMap<String, String>,
    context: &proxy::ProxyContext,
    options: &super::AdapterCommandOptions,
) {
    let endpoint = context.endpoint();
    set.insert("RUSTC_WRAPPER".to_string(), "sccache".to_string());
    insert_if_process_env_unset(set, "CARGO_INCREMENTAL", "0");
    insert_if_process_env_unset(set, "CC", "sccache cc");
    insert_if_process_env_unset(set, "CXX", "sccache c++");
    set.insert(
        "SCCACHE_WEBDAV_ENDPOINT".to_string(),
        format!("{endpoint}/"),
    );
    set.insert(
        "SCCACHE_WEBDAV_KEY_PREFIX".to_string(),
        options.sccache_key_prefix.clone().unwrap_or_default(),
    );
}

fn insert_if_process_env_unset(set: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        set.insert(key.to_string(), value.to_string());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SccacheStatsSummary {
    compile_requests: u64,
    cache_hits: u64,
    cache_misses: u64,
    rust_hit_rate: Option<String>,
}

pub(super) async fn print_stats_summary() {
    let output = match tokio::process::Command::new("sccache")
        .arg("--show-stats")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            ui::warn(&format!("Failed to read sccache stats: {error}"));
            return;
        }
    };

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    if let Some(summary) = summarize_sccache_stats(&combined) {
        ui::info(&format!(
            "[boringcache] sccache stats: compile_requests={} cache_hits={} cache_misses={}{}",
            summary.compile_requests,
            summary.cache_hits,
            summary.cache_misses,
            summary
                .rust_hit_rate
                .as_ref()
                .map(|rate| format!(" rust_hit_rate={rate}"))
                .unwrap_or_default()
        ));
    } else if !combined.trim().is_empty() && !output.status.success() {
        ui::warn("sccache stats were unavailable after the wrapped command");
    }
}

fn summarize_sccache_stats(output: &str) -> Option<SccacheStatsSummary> {
    if output.trim().is_empty() {
        return None;
    }

    Some(SccacheStatsSummary {
        compile_requests: parse_integer_stat(output, "Compile requests")?,
        cache_hits: parse_integer_stat(output, "Cache hits")?,
        cache_misses: parse_integer_stat(output, "Cache misses")?,
        rust_hit_rate: parse_text_stat(output, "Cache hits rate (Rust)"),
    })
}

fn parse_integer_stat(output: &str, label: &str) -> Option<u64> {
    let value = parse_text_stat(output, label)?;
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn parse_text_stat(output: &str, label: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line.trim_end().strip_prefix(label)?;
        if value.chars().take_while(|ch| ch.is_whitespace()).count() < 2 {
            return None;
        }
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::adapter::AdapterKind;
    use crate::test_env;

    #[test]
    fn sccache_env_plan_sets_webdav_backend() {
        let _guard = test_env::lock();
        test_env::remove_var("CARGO_INCREMENTAL");
        test_env::remove_var("CC");
        test_env::remove_var("CXX");

        let context = proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(
            &context,
            &super::super::AdapterCommandOptions {
                cache_ref_tag: "buildcache".to_string(),
                cache_mode: "max".to_string(),
                read_only: false,
                docker_oci_cache: None,
                sccache_key_prefix: None,
                gradle_home: None,
                node_package_manager_env: Default::default(),
                skip_actions: Vec::new(),
            },
        );
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_ENDPOINT"),
            Some(&"http://127.0.0.1:5000/".to_string())
        );
        assert_eq!(plan.set.get("RUSTC_WRAPPER"), Some(&"sccache".to_string()));
        assert_eq!(plan.set.get("CARGO_INCREMENTAL"), Some(&"0".to_string()));
        assert_eq!(plan.set.get("CC"), Some(&"sccache cc".to_string()));
        assert_eq!(plan.set.get("CXX"), Some(&"sccache c++".to_string()));
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_KEY_PREFIX"),
            Some(&String::new())
        );
    }

    #[test]
    fn sccache_env_plan_sets_configured_key_prefix() {
        let _guard = test_env::lock();
        test_env::remove_var("CARGO_INCREMENTAL");
        test_env::remove_var("CC");
        test_env::remove_var("CXX");

        let context = proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(
            &context,
            &super::super::AdapterCommandOptions {
                cache_ref_tag: "buildcache".to_string(),
                cache_mode: "max".to_string(),
                read_only: false,
                docker_oci_cache: None,
                sccache_key_prefix: Some("rust/ci".to_string()),
                gradle_home: None,
                node_package_manager_env: Default::default(),
                skip_actions: Vec::new(),
            },
        );
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_KEY_PREFIX"),
            Some(&"rust/ci".to_string())
        );
    }

    #[test]
    fn sccache_env_plan_preserves_user_cc_and_cxx() {
        let _guard = test_env::lock();
        test_env::set_var("CC", "clang");
        test_env::set_var("CXX", "clang++");

        let context = proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(
            &context,
            &super::super::AdapterCommandOptions {
                cache_ref_tag: "buildcache".to_string(),
                cache_mode: "max".to_string(),
                read_only: false,
                docker_oci_cache: None,
                sccache_key_prefix: None,
                gradle_home: None,
                node_package_manager_env: Default::default(),
                skip_actions: Vec::new(),
            },
        );
        assert!(!plan.set.contains_key("CC"));
        assert!(!plan.set.contains_key("CXX"));

        test_env::remove_var("CC");
        test_env::remove_var("CXX");
    }

    #[test]
    fn summarize_sccache_stats_reads_core_fields() {
        let output = r#"
Compile requests                     12
Cache hits                            7
Cache misses                          5
Cache hits rate (Rust)            58.33 %
"#;

        assert_eq!(
            summarize_sccache_stats(output),
            Some(SccacheStatsSummary {
                compile_requests: 12,
                cache_hits: 7,
                cache_misses: 5,
                rust_hit_rate: Some("58.33 %".to_string()),
            })
        );
    }

    #[test]
    fn summarize_sccache_stats_requires_numeric_core_fields() {
        let output = r#"
Compile requests                     none
Cache hits                            7
Cache misses                          5
"#;

        assert_eq!(summarize_sccache_stats(output), None);
    }
}

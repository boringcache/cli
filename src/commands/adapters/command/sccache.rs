use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use serde::Serialize;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;
use crate::ui;

const NATIVE_TOOL_SCHEMA_VERSION: &str = "native_tool_evidence.v1";
const SCCACHE_STATS_SOURCE: &str = "sccache --show-stats";

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

#[derive(Debug, Clone, PartialEq, Serialize)]
struct SccacheNativeToolEvidence {
    schema_version: &'static str,
    tool: &'static str,
    stats_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    compile_requests: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compile_requests_executed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_hits: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_misses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hit_rate: Option<f64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    hit_counts: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    miss_counts: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_cacheable_calls: Option<u64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    non_cacheable_reasons: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    average_cache_read_hit_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    average_cache_write_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    average_compiler_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_read_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_write_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_timeouts: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SccacheStatsSummary {
    compile_requests: u64,
    cache_hits: u64,
    cache_misses: u64,
    rust_hit_rate: Option<String>,
}

impl SccacheNativeToolEvidence {
    fn summary(&self, output: &str) -> Option<SccacheStatsSummary> {
        Some(SccacheStatsSummary {
            compile_requests: self.compile_requests?,
            cache_hits: self.cache_hits?,
            cache_misses: self.cache_misses?,
            rust_hit_rate: parse_text_stat(output, "Cache hits rate (Rust)"),
        })
    }
}

pub(super) async fn print_stats_summary(native_tool_evidence_json: Option<&str>) {
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

    let evidence = sccache_native_tool_evidence(&combined);
    if let (Some(path), Some(evidence)) = (native_tool_evidence_json, evidence.as_ref())
        && let Err(error) = write_native_tool_evidence(path, evidence).await
    {
        ui::warn(&format!(
            "Failed to write sccache native tool evidence: {error:#}"
        ));
    }

    if let Some(summary) = evidence
        .as_ref()
        .and_then(|evidence| evidence.summary(&combined))
    {
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
    } else if native_tool_evidence_json.is_some() && evidence.is_none() {
        ui::warn("sccache native tool evidence was unavailable after the wrapped command");
    }
}

#[cfg(test)]
fn summarize_sccache_stats(output: &str) -> Option<SccacheStatsSummary> {
    sccache_native_tool_evidence(output)?.summary(output)
}

fn sccache_native_tool_evidence(output: &str) -> Option<SccacheNativeToolEvidence> {
    if output.trim().is_empty() {
        return None;
    }

    let cache_hits = parse_integer_stat(output, "Cache hits");
    let cache_misses = parse_integer_stat(output, "Cache misses");
    let has_core_stats = parse_integer_stat(output, "Compile requests").is_some()
        || cache_hits.is_some()
        || cache_misses.is_some();
    if !has_core_stats {
        return None;
    }

    Some(SccacheNativeToolEvidence {
        schema_version: NATIVE_TOOL_SCHEMA_VERSION,
        tool: "sccache",
        stats_source: SCCACHE_STATS_SOURCE,
        compile_requests: parse_integer_stat(output, "Compile requests"),
        compile_requests_executed: parse_integer_stat(output, "Compile requests executed"),
        cache_hits,
        cache_misses,
        hit_rate: hit_rate(cache_hits, cache_misses),
        hit_counts: parse_grouped_integer_stats(output, "Cache hits"),
        miss_counts: parse_grouped_integer_stats(output, "Cache misses"),
        non_cacheable_calls: parse_integer_stat(output, "Non-cacheable calls")
            .or_else(|| parse_integer_stat(output, "Non-cacheable compilations")),
        non_cacheable_reasons: parse_non_cacheable_reasons(output),
        average_cache_read_hit_seconds: parse_seconds_stat(output, "Average cache read hit"),
        average_cache_write_seconds: parse_seconds_stat(output, "Average cache write"),
        average_compiler_seconds: parse_seconds_stat(output, "Average compiler"),
        cache_errors: parse_integer_stat(output, "Cache errors"),
        cache_read_errors: parse_integer_stat(output, "Cache read errors"),
        cache_write_errors: parse_integer_stat(output, "Cache write errors"),
        cache_timeouts: parse_integer_stat(output, "Cache timeouts"),
    })
}

async fn write_native_tool_evidence(
    path: &str,
    evidence: &SccacheNativeToolEvidence,
) -> Result<()> {
    let path = Path::new(path);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    let json = serde_json::to_vec_pretty(evidence)
        .context("Failed to serialize sccache native tool evidence")?;
    tokio::fs::write(path, json)
        .await
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn parse_integer_stat(output: &str, label: &str) -> Option<u64> {
    let value = parse_text_stat(output, label)?.replace(',', "");
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn parse_text_stat(output: &str, label: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line.trim().strip_prefix(label)?;
        if value.chars().take_while(|ch| ch.is_whitespace()).count() < 2 {
            return None;
        }
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn parse_seconds_stat(output: &str, label: &str) -> Option<f64> {
    let value = parse_text_stat(output, label)?;
    value.split_whitespace().next()?.parse().ok()
}

fn parse_grouped_integer_stats(output: &str, label: &str) -> BTreeMap<String, u64> {
    let prefix = format!("{label} (");
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(&prefix)?;
            let (raw_key, value) = rest.split_once(')')?;
            let value = value.trim().replace(',', "");
            if value.chars().all(|ch| ch.is_ascii_digit()) {
                Some((normalize_sccache_count_key(raw_key), value.parse().ok()?))
            } else {
                None
            }
        })
        .filter(|(key, _)| !key.is_empty())
        .collect()
}

fn parse_non_cacheable_reasons(output: &str) -> BTreeMap<String, u64> {
    let mut reasons = BTreeMap::new();
    let mut in_reasons = false;

    for line in output.lines() {
        let line = line.trim();
        if line == "Non-cacheable reasons:" {
            in_reasons = true;
            continue;
        }

        if !in_reasons {
            continue;
        }

        if line.is_empty() {
            break;
        }

        if let Some((key, value)) = split_integer_stat_line(line)
            && !key.is_empty()
        {
            reasons.insert(key.to_string(), value);
        }
    }

    reasons
}

fn split_integer_stat_line(line: &str) -> Option<(&str, u64)> {
    let line = line.trim();
    let value_start = line.rfind(|ch: char| !ch.is_ascii_digit())? + 1;
    let key = line[..value_start].trim();
    let value = line[value_start..].trim().replace(',', "");
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        Some((key, value.parse().ok()?))
    } else {
        None
    }
}

fn normalize_sccache_count_key(raw: &str) -> String {
    let raw = raw
        .trim()
        .to_ascii_lowercase()
        .replace("c/c++", "c_cpp")
        .replace("c++", "cpp");
    let mut normalized = String::new();
    let mut previous_was_separator = false;

    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch);
            previous_was_separator = false;
        } else if !previous_was_separator {
            normalized.push('_');
            previous_was_separator = true;
        }
    }

    normalized.trim_matches('_').to_string()
}

fn hit_rate(cache_hits: Option<u64>, cache_misses: Option<u64>) -> Option<f64> {
    let cache_hits = cache_hits?;
    let cache_misses = cache_misses?;
    let total = cache_hits + cache_misses;
    if total == 0 {
        None
    } else {
        Some(((cache_hits as f64 * 1000.0) / total as f64).round() / 10.0)
    }
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
                buildkit_cache_tag: "buildcache".to_string(),
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
                buildkit_cache_tag: "buildcache".to_string(),
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
                buildkit_cache_tag: "buildcache".to_string(),
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

    #[test]
    fn sccache_native_tool_evidence_reads_full_stats() {
        let output = r#"
Compile requests                  2613
Compile requests executed         2305
Cache hits                        2173
Cache hits (C/C++)                 666
Cache hits (Rust)                 1366
Cache misses                       124
Cache misses (Rust)                124
Cache hits rate                  94.60 %
Cache hits rate (Rust)           91.68 %
Cache timeouts                       0
Cache read errors                    1
Cache write errors                   2
Cache errors                         3
Non-cacheable calls                299
Average cache read hit           0.004 s
Average cache write              0.011 s
Average compiler                29.316 s

Non-cacheable reasons:
crate-type                        252
-o                                 30
missing input                       6

Cache location                  webdav, name: , prefix: /
"#;

        let evidence = sccache_native_tool_evidence(output).expect("evidence");

        assert_eq!(evidence.tool, "sccache");
        assert_eq!(evidence.schema_version, "native_tool_evidence.v1");
        assert_eq!(evidence.compile_requests, Some(2613));
        assert_eq!(evidence.compile_requests_executed, Some(2305));
        assert_eq!(evidence.cache_hits, Some(2173));
        assert_eq!(evidence.cache_misses, Some(124));
        assert_eq!(evidence.hit_rate, Some(94.6));
        assert_eq!(evidence.hit_counts.get("c_cpp"), Some(&666));
        assert_eq!(evidence.hit_counts.get("rust"), Some(&1366));
        assert_eq!(evidence.miss_counts.get("rust"), Some(&124));
        assert_eq!(evidence.non_cacheable_calls, Some(299));
        assert_eq!(evidence.non_cacheable_reasons.get("crate-type"), Some(&252));
        assert_eq!(evidence.non_cacheable_reasons.get("-o"), Some(&30));
        assert_eq!(
            evidence.non_cacheable_reasons.get("missing input"),
            Some(&6)
        );
        assert_eq!(evidence.average_cache_read_hit_seconds, Some(0.004));
        assert_eq!(evidence.average_cache_write_seconds, Some(0.011));
        assert_eq!(evidence.average_compiler_seconds, Some(29.316));
        assert_eq!(evidence.cache_errors, Some(3));
        assert_eq!(evidence.cache_read_errors, Some(1));
        assert_eq!(evidence.cache_write_errors, Some(2));
        assert_eq!(evidence.cache_timeouts, Some(0));

        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["tool"], "sccache");
        assert_eq!(json["hit_counts"]["c_cpp"], 666);
        assert_eq!(json["non_cacheable_reasons"]["-o"], 30);
    }

    #[tokio::test]
    async fn write_native_tool_evidence_creates_parent_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("nested/native-tool.json");
        let evidence = sccache_native_tool_evidence(
            r#"
Compile requests                      7
Cache hits                            1
Cache misses                          6
"#,
        )
        .expect("evidence");

        write_native_tool_evidence(path.to_str().unwrap(), &evidence)
            .await
            .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(json["schema_version"], "native_tool_evidence.v1");
        assert_eq!(json["cache_hits"], 1);
        assert_eq!(json["cache_misses"], 6);
        assert_eq!(json["hit_rate"], 14.3);
    }
}

use anyhow::{Result, ensure};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::project_config::SkipRuleConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySkipRule {
    pub tool: String,
    pub action: String,
    pub reason: Option<String>,
}

impl ProxySkipRule {
    fn from_config(config: &SkipRuleConfig) -> Result<Self> {
        let raw_tool = config.tool.as_deref().unwrap_or_default().trim();
        let action = config.action.as_deref().unwrap_or_default().trim();
        ensure!(!raw_tool.is_empty(), "[[skip]] rule is missing tool");
        ensure!(!action.is_empty(), "[[skip]] rule is missing action");

        let tool = canonical_skip_tool(raw_tool)
            .ok_or_else(|| anyhow::anyhow!("unsupported [[skip]] tool: {raw_tool}"))?;
        let reason = config
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        Ok(Self {
            tool: tool.to_string(),
            action: action.to_string(),
            reason,
        })
    }

    pub fn matches(&self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

pub fn proxy_skip_rules_from_config(configs: &[SkipRuleConfig]) -> Result<Vec<ProxySkipRule>> {
    configs.iter().map(ProxySkipRule::from_config).collect()
}

fn canonical_skip_tool(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "runtime" => Some("runtime"),
        "turborepo" | "turbo" => Some("turborepo"),
        "nx" => Some("nx"),
        "bazel" => Some("bazel"),
        "gradle" => Some("gradle"),
        "maven" => Some("maven"),
        "sccache" => Some("sccache"),
        "gocache" | "go" | "go-cache" | "go-cacheprog" => Some("gocache"),
        "oci" | "docker" | "buildkit" | "docker-registry" => Some("oci"),
        _ => None,
    }
}

#[derive(Default)]
pub struct ProxySkipRuleMetrics {
    matched_count: AtomicU64,
}

impl ProxySkipRuleMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_match(&self) {
        self.matched_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn matched_count(&self) -> u64 {
        self.matched_count.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_rules_canonicalize_tool_aliases() {
        let rules = proxy_skip_rules_from_config(&[SkipRuleConfig {
            tool: Some("turbo".to_string()),
            action: Some("build".to_string()),
            reason: Some("too cheap".to_string()),
        }])
        .expect("valid rule");

        assert_eq!(rules[0].tool, "turborepo");
        assert!(rules[0].matches("turborepo", "build"));
        assert_eq!(rules[0].reason.as_deref(), Some("too cheap"));
    }

    #[test]
    fn skip_rules_reject_missing_action() {
        let error = proxy_skip_rules_from_config(&[SkipRuleConfig {
            tool: Some("gradle".to_string()),
            action: None,
            reason: None,
        }])
        .unwrap_err();

        assert!(error.to_string().contains("missing action"));
    }
}

use crate::api::ApiClient;
use crate::ui;
use anyhow::{Result, anyhow};
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct CheckOptions {
    pub no_platform: bool,
    pub no_git: bool,
    pub fail_on_miss: bool,
    pub json_output: bool,
    pub require_server_signature: bool,
    pub exact: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub tag: String,
    pub requested_tag: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CheckSummary {
    pub workspace: String,
    pub total: usize,
    pub hits: usize,
    pub misses: usize,
    pub results: Vec<CheckResult>,
}

pub async fn execute(
    workspace: Option<String>,
    tags: Vec<String>,
    options: CheckOptions,
) -> Result<()> {
    if let Err(err) = execute_inner(workspace, tags, options).await {
        if options.fail_on_miss || options.require_server_signature {
            return Err(err);
        }
        ui::warn(&format!("{:#}", err));
    }
    Ok(())
}

async fn execute_inner(
    workspace: Option<String>,
    tags: Vec<String>,
    options: CheckOptions,
) -> Result<()> {
    let workspace = crate::command_support::get_workspace_name(workspace)?;

    if tags.is_empty() {
        if options.json_output {
            let summary = CheckSummary {
                workspace: workspace.clone(),
                total: 0,
                hits: 0,
                misses: 0,
                results: vec![],
            };
            crate::json_output::print(&summary)?;
        } else {
            ui::info("No tags specified to check");
        }
        return Ok(());
    }

    crate::api::parse_workspace_slug(&workspace)?;

    let mut valid_tags: Vec<String> = Vec::new();
    for tag in tags {
        let validation_result = crate::tag_utils::validate_tag(&tag);
        match validation_result {
            Ok(()) => valid_tags.push(tag),
            Err(err) => {
                ui::warn(&format!("Skipping invalid tag '{}': {}", tag, err));
            }
        }
    }

    if valid_tags.is_empty() {
        if options.json_output {
            let summary = CheckSummary {
                workspace: workspace.clone(),
                total: 0,
                hits: 0,
                misses: 0,
                results: vec![],
            };
            crate::json_output::print(&summary)?;
        } else {
            ui::warn("No valid tags to check");
        }
        return Ok(());
    }

    let platform = if options.no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };

    let git_enabled = !options.no_git && !crate::git::is_git_disabled_by_env();

    let mut all_candidates: Vec<String> = Vec::new();
    let mut tag_to_candidates: Vec<(String, Vec<String>)> = Vec::new();

    for tag in &valid_tags {
        let git_context = if git_enabled {
            crate::git::GitContext::detect()
        } else {
            crate::git::GitContext::default()
        };

        let resolver =
            crate::tag_utils::TagResolver::new(platform.clone(), git_context, git_enabled);
        let candidates = if options.exact {
            vec![resolver.effective_save_tag(tag)?]
        } else {
            resolver.restore_tag_candidates(tag)
        };

        for candidate in &candidates {
            if !all_candidates.contains(candidate) {
                all_candidates.push(candidate.clone());
            }
        }

        tag_to_candidates.push((tag.clone(), candidates));
    }

    let api_client = ApiClient::for_restore()?;

    if !options.json_output {
        ui::info(&format!(
            "Checking {} tag{} in {}",
            valid_tags.len(),
            if valid_tags.len() == 1 { "" } else { "s" },
            workspace
        ));
    }

    let resolution_result = api_client
        .restore(
            &workspace,
            &all_candidates,
            options.require_server_signature,
        )
        .await?;

    let mut results_by_tag: std::collections::HashMap<String, crate::api::CacheResolutionEntry> =
        std::collections::HashMap::new();
    for entry in resolution_result {
        if options.require_server_signature && entry.status == "hit" {
            verify_check_signature(&entry)?;
        }
        results_by_tag.insert(entry.tag.clone(), entry);
    }

    let mut check_results: Vec<CheckResult> = Vec::new();
    let mut hits = 0usize;
    let mut misses = 0usize;

    for (requested_tag, candidates) in &tag_to_candidates {
        let mut found: Option<(String, &crate::api::CacheResolutionEntry)> = None;
        for candidate in candidates {
            if let Some(entry) = results_by_tag.get(candidate)
                && entry.status == "hit"
            {
                found = Some((candidate.clone(), entry));
                break;
            }
        }

        if let Some((matched_tag, entry)) = found {
            hits += 1;
            check_results.push(CheckResult {
                tag: matched_tag,
                requested_tag: requested_tag.clone(),
                status: "hit".to_string(),
                size: entry.size,
                compressed_size: entry.compressed_size,
            });
        } else {
            misses += 1;

            let display_tag = candidates
                .first()
                .cloned()
                .unwrap_or_else(|| requested_tag.clone());
            check_results.push(CheckResult {
                tag: display_tag,
                requested_tag: requested_tag.clone(),
                status: "miss".to_string(),
                size: None,
                compressed_size: None,
            });
        }
    }

    let missing_tags: Vec<String> = check_results
        .iter()
        .filter(|r| r.status == "miss")
        .map(|r| r.requested_tag.clone())
        .collect();

    if options.json_output {
        let summary = CheckSummary {
            workspace: workspace.clone(),
            total: check_results.len(),
            hits,
            misses,
            results: check_results,
        };
        crate::json_output::print(&summary)?;
    } else {
        ui::blank_line();
        for result in &check_results {
            let status_icon = if result.status == "hit" { "+" } else { "-" };
            let size_info = match (result.compressed_size, result.size) {
                (Some(compressed), Some(uncompressed)) if compressed < uncompressed => {
                    format!(
                        " ({} stored, {} uncompressed)",
                        crate::progress::format_bytes(compressed),
                        crate::progress::format_bytes(uncompressed)
                    )
                }
                (Some(size), _) | (_, Some(size)) => {
                    format!(" ({})", crate::progress::format_bytes(size))
                }
                _ => String::new(),
            };

            if result.tag != result.requested_tag {
                ui::info(&format!(
                    "  {} {} -> {}{}",
                    status_icon, result.requested_tag, result.tag, size_info
                ));
            } else {
                ui::info(&format!("  {} {}{}", status_icon, result.tag, size_info));
            }
        }

        ui::blank_line();
        ui::info(&format!(
            "Result: {}/{} cache entries found",
            hits,
            check_results.len()
        ));

        if !missing_tags.is_empty() {
            ui::warn(&format!("Missing: {}", missing_tags.join(", ")));
        }
    }

    if options.fail_on_miss && !missing_tags.is_empty() {
        anyhow::bail!("Cache miss for tags: {}", missing_tags.join(", "));
    }

    Ok(())
}

fn verify_check_signature(entry: &crate::api::CacheResolutionEntry) -> Result<()> {
    let root_digest = entry.manifest_root_digest.as_deref().ok_or_else(|| {
        anyhow!(
            "Signed cache hit for {} is missing manifest_root_digest",
            entry.tag
        )
    })?;
    let signature_tag = entry
        .signature_tag
        .as_deref()
        .or(entry.primary_tag.as_deref())
        .unwrap_or(entry.tag.as_str());
    let public_key = entry
        .workspace_signing_public_key
        .as_deref()
        .ok_or_else(|| {
            anyhow!(
                "Workspace signing key missing for {}; strict signature mode is enabled",
                signature_tag
            )
        })?;
    let server_signature = entry.server_signature.as_deref().ok_or_else(|| {
        anyhow!(
            "Server signature missing for {}; strict signature mode is enabled",
            signature_tag
        )
    })?;

    crate::signing::policy::verify_server_signature(
        signature_tag,
        root_digest,
        public_key,
        server_signature,
    )
    .map_err(|error| {
        anyhow!(
            "Server signature verification failed for {}: {}",
            signature_tag,
            error
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_json_contract_adds_schema_version() {
        let summary = CheckSummary {
            workspace: "org/demo".to_string(),
            total: 2,
            hits: 1,
            misses: 1,
            results: vec![
                CheckResult {
                    tag: "deps-main".to_string(),
                    requested_tag: "deps".to_string(),
                    status: "hit".to_string(),
                    size: Some(1024),
                    compressed_size: Some(512),
                },
                CheckResult {
                    tag: "deps-fallback".to_string(),
                    requested_tag: "deps-fallback".to_string(),
                    status: "miss".to_string(),
                    size: None,
                    compressed_size: None,
                },
            ],
        };

        let value = crate::json_output::to_value(&summary).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["workspace"], "org/demo");
        assert_eq!(value["results"][0]["status"], "hit");
    }
}

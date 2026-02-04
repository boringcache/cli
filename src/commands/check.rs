use crate::api::ApiClient;
use crate::ui;
use anyhow::Result;
use serde::Serialize;

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
    no_platform: bool,
    no_git: bool,
    fail_on_miss: bool,
    json_output: bool,
) -> Result<()> {
    if let Err(err) = execute_inner(
        workspace,
        tags,
        no_platform,
        no_git,
        fail_on_miss,
        json_output,
    )
    .await
    {
        if fail_on_miss {
            return Err(err);
        }
        ui::warn(&format!("{:#}", err));
    }
    Ok(())
}

async fn execute_inner(
    workspace: Option<String>,
    tags: Vec<String>,
    no_platform: bool,
    no_git: bool,
    fail_on_miss: bool,
    json_output: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace)?;

    if tags.is_empty() {
        if json_output {
            let summary = CheckSummary {
                workspace: workspace.clone(),
                total: 0,
                hits: 0,
                misses: 0,
                results: vec![],
            };
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            ui::info("No tags specified to check");
        }
        return Ok(());
    }

    crate::api::parse_workspace_slug(&workspace)?;

    let mut valid_tags: Vec<String> = Vec::new();
    for tag in tags {
        match crate::tag_utils::validate_tag(&tag) {
            Ok(()) => valid_tags.push(tag),
            Err(err) => {
                ui::warn(&format!("Skipping invalid tag '{}': {}", tag, err));
            }
        }
    }

    if valid_tags.is_empty() {
        if json_output {
            let summary = CheckSummary {
                workspace: workspace.clone(),
                total: 0,
                hits: 0,
                misses: 0,
                results: vec![],
            };
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            ui::warn("No valid tags to check");
        }
        return Ok(());
    }

    let platform = if no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };

    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();

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
        let candidates = resolver.restore_tag_candidates(tag);

        for candidate in &candidates {
            if !all_candidates.contains(candidate) {
                all_candidates.push(candidate.clone());
            }
        }

        tag_to_candidates.push((tag.clone(), candidates));
    }

    let api_client = ApiClient::new()?;

    if !json_output {
        ui::info(&format!(
            "Checking {} tag{} in {}",
            valid_tags.len(),
            if valid_tags.len() == 1 { "" } else { "s" },
            workspace
        ));
    }

    let resolution_result = api_client.restore(&workspace, &all_candidates).await?;

    let mut results_by_tag: std::collections::HashMap<String, crate::api::CacheResolutionEntry> =
        std::collections::HashMap::new();
    for entry in resolution_result {
        results_by_tag.insert(entry.tag.clone(), entry);
    }

    let mut check_results: Vec<CheckResult> = Vec::new();
    let mut hits = 0usize;
    let mut misses = 0usize;

    for (requested_tag, candidates) in &tag_to_candidates {
        let mut found: Option<(String, &crate::api::CacheResolutionEntry)> = None;
        for candidate in candidates {
            if let Some(entry) = results_by_tag.get(candidate) {
                if entry.status == "hit" {
                    found = Some((candidate.clone(), entry));
                    break;
                }
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

    if json_output {
        let summary = CheckSummary {
            workspace: workspace.clone(),
            total: check_results.len(),
            hits,
            misses,
            results: check_results,
        };
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        ui::blank_line();
        for result in &check_results {
            let status_icon = if result.status == "hit" { "+" } else { "-" };
            let size_info = if let Some(size) = result.size {
                format!(" ({})", crate::progress::format_bytes(size))
            } else {
                String::new()
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

    if fail_on_miss && !missing_tags.is_empty() {
        anyhow::bail!("Cache miss for tags: {}", missing_tags.join(", "));
    }

    Ok(())
}

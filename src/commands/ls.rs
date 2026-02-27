use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::time::Instant;

use crate::api::ApiClient;
use crate::progress::format_bytes;
use crate::ui;

#[derive(Debug, Serialize)]
struct LsEntrySummary {
    id: String,
    manifest_root_digest: String,
    tag: Option<String>,
    status: String,
    total_size_bytes: u64,
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    file_count: Option<u32>,
    compression_algorithm: String,
    created_at: String,
    uploaded_at: Option<String>,
    encrypted: bool,
}

#[derive(Debug, Serialize)]
struct LsSummary {
    workspace: String,
    total: u32,
    page: u32,
    limit: u32,
    entries: Vec<LsEntrySummary>,
}

pub async fn execute(
    workspace_option: Option<String>,
    limit: Option<u32>,
    page: Option<u32>,
    verbose: bool,
    json_output: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let start_time = Instant::now();
    let api_client = ApiClient::new()?;

    if verbose {
        ui::info(&format!("Listing cache entries for: {workspace}"));
    }

    let response = api_client.list(&workspace, limit, page).await?;

    let mut entries = response.entries;
    entries.sort_by(|a, b| {
        let a_time = a.uploaded_at.as_ref().unwrap_or(&a.created_at);
        let b_time = b.uploaded_at.as_ref().unwrap_or(&b.created_at);
        b_time.cmp(a_time)
    });

    if json_output {
        let summary = LsSummary {
            workspace: workspace.clone(),
            total: response.total,
            page: response.page,
            limit: response.limit,
            entries: entries
                .into_iter()
                .map(|entry| LsEntrySummary {
                    status: if entry.uploaded_at.is_some() {
                        "ready".to_string()
                    } else {
                        "pending".to_string()
                    },
                    id: entry.id,
                    manifest_root_digest: entry.manifest_root_digest,
                    tag: entry.tag,
                    total_size_bytes: entry.total_size_bytes,
                    uncompressed_size: entry.uncompressed_size,
                    compressed_size: entry.compressed_size,
                    file_count: entry.file_count,
                    compression_algorithm: entry.compression_algorithm,
                    created_at: entry.created_at,
                    uploaded_at: entry.uploaded_at,
                    encrypted: entry.encrypted,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    if entries.is_empty() {
        ui::info(&format!(
            "No cache entries found for workspace: {workspace}"
        ));
        return Ok(());
    }

    println!();
    if verbose {
        println!(
            "{:<24} {:<20} {:<14} {:<14} {:<16} {:<12}",
            "TAG", "STATUS", "STORED", "UNCOMPRESSED", "UPLOADED", "COMPRESSION"
        );
        println!("{}", "-".repeat(104));
    } else {
        println!(
            "{:<24} {:<20} {:<14} {:<14} {:<16}",
            "TAG", "STATUS", "STORED", "UNCOMPRESSED", "UPLOADED"
        );
        println!("{}", "-".repeat(92));
    }

    for entry in &entries {
        let tag_value = entry
            .tag
            .clone()
            .unwrap_or_else(|| "(untagged)".to_string());
        let tag = if tag_value.len() > 24 {
            format!("{}...", &tag_value[..21])
        } else {
            tag_value
        };

        let base_status = if entry.uploaded_at.is_some() {
            "ready"
        } else {
            "pending"
        };
        let status = build_status_string(base_status, entry.encrypted);
        let stored = format_bytes(entry.total_size_bytes);
        let uncompressed = entry
            .uncompressed_size
            .map(format_bytes)
            .unwrap_or_else(|| "-".to_string());
        let created = format_created_at(entry.uploaded_at.as_ref().or(Some(&entry.created_at)));

        if verbose {
            let compression = entry.compression_algorithm.as_str();
            println!(
                "{tag:<24} {status:<20} {stored:<14} {uncompressed:<14} {created:<16} {compression:<12}",
                tag = tag,
                status = status,
                stored = stored,
                uncompressed = uncompressed,
                created = created,
                compression = compression,
            );
        } else {
            println!(
                "{tag:<24} {status:<20} {stored:<14} {uncompressed:<14} {created:<16}",
                tag = tag,
                status = status,
                stored = stored,
                uncompressed = uncompressed,
                created = created
            );
        }
    }

    ui::blank_line();
    ui::info(&format!("Total: {} entries", entries.len()));

    if response.total > entries.len() as u32 {
        ui::info(&format!(
            "Showing {} of {} entries (page {} of {})",
            entries.len(),
            response.total,
            response.page,
            response.total.div_ceil(response.limit)
        ));
    }

    if verbose {
        let duration = start_time.elapsed();
        ui::info(&format!("⏱️  Listed in {:.2}s", duration.as_secs_f64()));
    }

    Ok(())
}

fn build_status_string(base: &str, encrypted: bool) -> String {
    if encrypted {
        format!("{}, encrypted", base)
    } else {
        base.to_string()
    }
}

fn format_created_at(timestamp: Option<&String>) -> String {
    let Some(created_at) = timestamp else {
        return "-".to_string();
    };

    if let Ok(dt) = DateTime::parse_from_rfc3339(created_at) {
        let utc_dt: DateTime<Utc> = dt.into();
        let now = Utc::now();
        let diff = now.signed_duration_since(utc_dt);

        if diff.num_days() > 0 {
            format!("{} days ago", diff.num_days())
        } else if diff.num_hours() > 0 {
            format!("{} hours ago", diff.num_hours())
        } else if diff.num_minutes() > 0 {
            format!("{} minutes ago", diff.num_minutes())
        } else {
            "Just now".to_string()
        }
    } else {
        created_at.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_created_at() {
        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        let formatted = format_created_at(Some(&one_hour_ago.to_rfc3339()));
        assert!(formatted.contains("hour"));
    }
}

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::Instant;

use crate::api::ApiClient;
use crate::progress::format_bytes;
use crate::ui;

pub async fn execute(
    workspace_option: Option<String>,
    limit: Option<u32>,
    page: Option<u32>,
    verbose: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let start_time = Instant::now();
    let api_client = ApiClient::new()?;

    if verbose {
        ui::info(&format!("Listing cache entries for: {workspace}"));
    }

    let response = api_client.list(&workspace, limit, page).await?;

    if response.entries.is_empty() {
        ui::info(&format!(
            "No cache entries found for workspace: {workspace}"
        ));
        return Ok(());
    }

    println!();
    if verbose {
        println!(
            "{:<24} {:<15} {:<20} {:<20} {:<12}",
            "TAG", "STATUS", "SIZE", "UPLOADED", "COMPRESSION"
        );
        println!("{}", "-".repeat(96));
    } else {
        println!(
            "{:<24} {:<15} {:<20} {:<20}",
            "TAG", "STATUS", "SIZE", "UPLOADED"
        );
        println!("{}", "-".repeat(79));
    }

    let mut entries = response.entries;
    entries.sort_by(|a, b| {
        let a_time = a.uploaded_at.as_ref().unwrap_or(&a.created_at);
        let b_time = b.uploaded_at.as_ref().unwrap_or(&b.created_at);
        b_time.cmp(a_time)
    });

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

        let status = if entry.uploaded_at.is_some() {
            "ready"
        } else {
            "pending"
        };
        let size = format_bytes(entry.total_size_bytes);
        let created = format_created_at(entry.uploaded_at.as_ref().or(Some(&entry.created_at)));

        if verbose {
            let compression = entry.compression_algorithm.as_str();
            println!(
                "{tag:<24} {status:<15} {size:<20} {created:<20} {compression:<12}",
                tag = tag,
                status = status,
                size = size,
                created = created,
                compression = compression,
            );
        } else {
            println!(
                "{tag:<24} {status:<15} {size:<20} {created:<20}",
                tag = tag,
                status = status,
                size = size,
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

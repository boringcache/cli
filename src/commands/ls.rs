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

    let response = api_client.list_caches(&workspace, limit, page).await?;

    if response.entries.is_empty() {
        ui::info(&format!(
            "No cache entries found for workspace: {workspace}"
        ));
        return Ok(());
    }

    println!();
    if verbose {
        println!(
            "{:<18} {:<15} {:<15} {:<20} {:<12}",
            "USER TAG", "PLATFORM", "SIZE", "CREATED", "COMPRESSION"
        );
        println!("{}", "-".repeat(80));
    } else {
        println!(
            "{:<18} {:<15} {:<15} {:<20}",
            "USER TAG", "PLATFORM", "SIZE", "CREATED"
        );
        println!("{}", "-".repeat(68));
    }

    let mut entries = response.entries;
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    for entry in &entries {
        let (user_tag, platform) = if let Some(tag) = &entry.tag {
            let display_tag = if tag.len() > 18 {
                format!("{}...", &tag[..15.min(tag.len())])
            } else {
                tag.clone()
            };
            // Simplified: no platform parsing since we removed tag command
            (display_tag, "-".to_string())
        } else {
            ("-".to_string(), "-".to_string())
        };

        let size = format_bytes(entry.size);
        let created = format_created_at(&entry.created_at);

        if verbose {
            let compression = entry.compression_algorithm.as_str();
            println!("{user_tag:<18} {platform:<15} {size:<15} {created:<20} {compression:<12}");
        } else {
            println!("{user_tag:<18} {platform:<15} {size:<15} {created:<20}");
        }
    }

    println!();
    println!("Total: {} entries", entries.len());

    if response.total > entries.len() as u32 {
        println!(
            "Showing {} of {} entries (page {} of {})",
            entries.len(),
            response.total,
            response.page,
            response.total.div_ceil(response.limit)
        );
    }

    if verbose {
        let duration = start_time.elapsed();
        println!("⏱️  Listed in {:.2}s", duration.as_secs_f64());
    }

    Ok(())
}

fn format_created_at(created_at: &str) -> String {
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
        let formatted = format_created_at(&one_hour_ago.to_rfc3339());
        assert!(formatted.contains("hour"));
    }
}

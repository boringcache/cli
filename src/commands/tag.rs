use anyhow::Result;
use std::time::Instant;

use crate::api::ApiClient;
use crate::progress::format_bytes;
use crate::tag_utils::Tag;
use crate::ui::CleanUI;

pub async fn execute_list(
    workspace_option: Option<String>,
    filter: Option<String>,
    verbose: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let start_time = Instant::now();
    let api_client = ApiClient::new(None)?;

    CleanUI::info(&format!("📋 Listing tags for workspace: {workspace}"));

    let response = api_client.list_caches(&workspace, None, None).await?;

    if response.entries.is_empty() {
        CleanUI::info("No tags found");
        return Ok(());
    }

    // Group by user tag
    let mut grouped_tags: std::collections::HashMap<
        String,
        Vec<(String, &crate::api::CacheEntry)>,
    > = std::collections::HashMap::new();

    for entry in &response.entries {
        if let Some(tag) = &entry.tag {
            let parsed = Tag::from_existing(tag);

            if let Some(ref filter_str) = filter {
                if !parsed.user_tag.contains(filter_str) {
                    continue;
                }
            }

            let platform = parsed.platform_suffix();

            grouped_tags
                .entry(parsed.user_tag)
                .or_default()
                .push((platform, entry));
        }
    }

    if grouped_tags.is_empty() {
        CleanUI::info("No tags match the filter");
        return Ok(());
    }

    println!();
    if verbose {
        println!(
            "{:<20} {:<15} {:<15} {:<20} {:<12}",
            "USER TAG", "PLATFORM", "SIZE", "CREATED", "COMPRESSION"
        );
        println!("{}", "-".repeat(82));
    } else {
        println!(
            "{:<20} {:<15} {:<15} {:<20}",
            "USER TAG", "PLATFORM", "SIZE", "CREATED"
        );
        println!("{}", "-".repeat(70));
    }

    // Sort by user tag
    let mut sorted_tags: Vec<_> = grouped_tags.into_iter().collect();
    sorted_tags.sort_by(|a, b| a.0.cmp(&b.0));

    let unique_user_tags = sorted_tags.len();

    for (user_tag, platforms) in sorted_tags {
        // Sort platforms within each user tag
        let mut sorted_platforms = platforms;
        sorted_platforms.sort_by(|a, b| a.0.cmp(&b.0));

        for (i, (platform, entry)) in sorted_platforms.iter().enumerate() {
            let display_user_tag = if i == 0 {
                user_tag.clone()
            } else {
                "".to_string()
            };

            let size = format_bytes(entry.size);
            let created = format_created_at(&entry.created_at);

            if verbose {
                let compression = entry.compression_algorithm.as_deref().unwrap_or("-");
                println!(
                    "{:<20} {:<15} {:<15} {:<20} {:<12}",
                    display_user_tag, platform, size, created, compression
                );
            } else {
                println!(
                    "{:<20} {:<15} {:<15} {:<20}",
                    display_user_tag, platform, size, created
                );
            }
        }

        if sorted_platforms.len() > 1 {
            println!(); // Add spacing between different user tags with multiple platforms
        }
    }

    println!();
    let total_platform_variants = response.entries.iter().filter(|e| e.tag.is_some()).count();

    if filter.is_some() {
        CleanUI::info(&format!(
            "Found {} user tags ({} platform variants) matching filter",
            unique_user_tags, total_platform_variants
        ));
    } else {
        CleanUI::info(&format!(
            "Total: {} unique user tags ({} platform variants)",
            unique_user_tags, total_platform_variants
        ));
    }

    if verbose {
        let duration = start_time.elapsed();
        CleanUI::info(&format!("⏱️  Listed in {:.2}s", duration.as_secs_f64()));
    }

    Ok(())
}

pub async fn execute_move(
    workspace_option: Option<String>,
    source_tag: String,
    dest_tag: String,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let _api_client = ApiClient::new(None)?;

    CleanUI::info(&format!(
        "🏷️  Moving tag '{}' → '{}' in workspace '{}'",
        source_tag, dest_tag, workspace
    ));

    // This would require a new API endpoint for moving tags
    // For now, show what would happen
    CleanUI::warning("Tag move functionality requires API endpoint implementation");
    CleanUI::info("This would:");
    CleanUI::info(&format!("  1. Find cache entry with tag '{}'", source_tag));
    CleanUI::info(&format!(
        "  2. Create new tag '{}' pointing to same content",
        dest_tag
    ));
    CleanUI::info(&format!("  3. Remove old tag '{}'", source_tag));
    CleanUI::info("  4. Clean up orphaned entries if needed");

    // TODO: Implement API call
    // api_client.move_tag(&workspace, &source_tag, &dest_tag).await?;

    Ok(())
}

pub async fn execute_copy(
    workspace_option: Option<String>,
    source_tag: String,
    dest_tag: String,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let _api_client = ApiClient::new(None)?;

    CleanUI::info(&format!(
        "🏷️  Copying tag '{}' → '{}' in workspace '{}'",
        source_tag, dest_tag, workspace
    ));

    // This would require API endpoint for copying tags
    CleanUI::warning("Tag copy functionality requires API endpoint implementation");
    CleanUI::info("This would:");
    CleanUI::info(&format!("  1. Find cache entry with tag '{}'", source_tag));
    CleanUI::info(&format!(
        "  2. Create new tag '{}' pointing to same content",
        dest_tag
    ));
    CleanUI::info(&format!("  3. Keep original tag '{}'", source_tag));

    // TODO: Implement API call
    // api_client.copy_tag(&workspace, &source_tag, &dest_tag).await?;

    Ok(())
}

pub async fn execute_info(workspace_option: Option<String>, tag: String) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let api_client = ApiClient::new(None)?;

    CleanUI::info(&format!(
        "🏷️  Tag info for '{}' in workspace '{}'",
        tag, workspace
    ));

    // For now, use the existing list endpoint and filter
    let response = api_client.list_caches(&workspace, None, None).await?;

    let platform_info = crate::platform::Platform::detect()?;
    let resolved_tag = crate::tag_utils::resolve_tag_for_restore(&tag, &platform_info, false)?;

    let matching_entry = response
        .entries
        .iter()
        .find(|entry| entry.tag.as_ref() == Some(&resolved_tag));

    if let Some(entry) = matching_entry {
        let parsed = Tag::from_existing(&resolved_tag);
        let platform = parsed.platform_suffix();

        println!();
        println!("📋 Tag Information:");
        println!("   User Tag:     {}", parsed.user_tag);
        println!("   Platform:     {}", platform);
        println!("   Full Tag:     {}", resolved_tag);
        println!("   Size:         {}", format_bytes(entry.size));
        println!("   Created:      {}", format_created_at(&entry.created_at));

        if let Some(compression) = &entry.compression_algorithm {
            println!("   Compression:  {}", compression);
        }
        println!();
    } else {
        CleanUI::warning(&format!(
            "Tag '{}' not found (looked for '{}')",
            tag, resolved_tag
        ));

        // Show similar tags
        let similar_tags: Vec<_> = response
            .entries
            .iter()
            .filter_map(|entry| entry.tag.as_ref())
            .filter(|t| {
                let parsed = Tag::from_existing(t);
                parsed.user_tag.contains(&tag) || tag.contains(&parsed.user_tag)
            })
            .take(5)
            .collect();

        if !similar_tags.is_empty() {
            CleanUI::info("Similar tags found:");
            for similar in similar_tags {
                let parsed = Tag::from_existing(similar);
                let platform = parsed.platform_suffix();
                CleanUI::info(&format!("  {} ({})", parsed.user_tag, platform));
            }
        }
    }

    Ok(())
}

fn format_created_at(created_at: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created_at) {
        let utc_dt: chrono::DateTime<chrono::Utc> = dt.into();
        let now = chrono::Utc::now();
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

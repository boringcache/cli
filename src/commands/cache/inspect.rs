use crate::api::{ApiClient, models::cache::CacheInspectResponse};
use crate::progress::format_bytes;
use crate::ui;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};

pub async fn execute(
    workspace_or_identifier: String,
    identifier: Option<String>,
    json_output: bool,
) -> Result<()> {
    let (workspace_option, target) = parse_inspect_args(workspace_or_identifier, identifier)?;
    let api_client = ApiClient::for_restore()?;
    let workspace = crate::command_support::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache inspect <workspace> <tag|id>",
    )
    .await?;

    let inspection = api_client
        .inspect_cache(&workspace, &target)
        .await?
        .ok_or_else(|| {
            anyhow!("No cache entry found for '{target}' in workspace '{workspace}'.")
        })?;

    if json_output {
        crate::json_output::print(&inspection)?;
        return Ok(());
    }

    render_inspection(&inspection);
    Ok(())
}

fn render_inspection(inspection: &CacheInspectResponse) {
    ui::blank_line();
    println!("Cache");
    print_field("Workspace", &inspection.workspace.slug);
    print_field(
        "Matched",
        &format!(
            "{} via {}",
            inspection.identifier.query, inspection.identifier.matched_by
        ),
    );
    print_field("Entry id", &inspection.entry.id);
    if let Some(primary_tag) = inspection.entry.primary_tag.as_deref() {
        print_field("Primary tag", primary_tag);
    }
    print_field("Status", &build_status_summary(inspection));
    print_field("Storage", &storage_summary(inspection));
    print_field("Stored", &format_bytes(inspection.entry.stored_size_bytes));
    if let Some(size) = inspection.entry.uncompressed_size {
        print_field("Uncompressed", &format_bytes(size));
    }
    if let Some(size) = inspection.entry.compressed_size {
        print_field("Compressed", &format_bytes(size));
    }
    if let Some(file_count) = inspection.entry.file_count {
        print_field("Files", &file_count.to_string());
    }
    print_field("Hits", &inspection.entry.hit_count.to_string());
    print_field(
        "Uploaded",
        &format_relative_time(inspection.entry.uploaded_at.as_deref()),
    );
    print_field(
        "Last accessed",
        &format_relative_time(inspection.entry.last_accessed_at.as_deref()),
    );
    print_field("Digest", &inspection.entry.manifest_root_digest);
    if let Some(manifest_digest) = inspection.entry.manifest_digest.as_deref() {
        print_field("Manifest", manifest_digest);
    }
    if let Some(versions) = inspection.versions.as_ref() {
        print_field(
            "Versions",
            &format!(
                "{} / {} kept for {}{}",
                versions.version_count,
                versions.max_versions,
                versions.tag,
                if versions.current {
                    ""
                } else {
                    " (historical entry)"
                }
            ),
        );
    }
    ui::blank_line();

    println!("Tags");
    if inspection.tags.is_empty() {
        println!("  none");
    } else {
        for tag in &inspection.tags {
            let mut labels = Vec::new();
            if tag.primary {
                labels.push("primary");
            }
            if tag.system {
                labels.push("system");
            }
            if labels.is_empty() {
                println!("  {}", tag.name);
            } else {
                println!("  {} ({})", tag.name, labels.join(", "));
            }
        }
    }
    ui::blank_line();

    println!("Commands");
    print_field("Restore", &restore_command(inspection));
    print_field("Save", &save_command(inspection));
    match remove_command(inspection) {
        Some(command) => print_field("Remove", &command),
        None => print_field("Remove", "No human tag is bound to this cache entry"),
    }
    ui::blank_line();

    println!("Performance");
    if let Some(performance) = inspection.performance.as_ref() {
        print_field("Operations", &performance.total_operations.to_string());
        print_field("Restores", &performance.restores.to_string());
        print_field("Saves", &performance.saves.to_string());
        print_field("Errors", &performance.errors.to_string());
        print_field("Avg restore", &format_millis(performance.avg_restore_ms));
        print_field("Avg save", &format_millis(performance.avg_save_ms));
        print_field(
            "Last operation",
            &format_relative_time(performance.last_operation.as_deref()),
        );
    } else {
        println!("  No recent metrics recorded");
    }
}

fn build_status_summary(inspection: &CacheInspectResponse) -> String {
    let mut parts = vec![inspection.entry.status.clone()];
    if inspection.entry.encrypted {
        parts.push("encrypted".to_string());
    }
    if inspection.entry.server_signed {
        parts.push("signed".to_string());
    }
    parts.join(", ")
}

fn storage_summary(inspection: &CacheInspectResponse) -> String {
    if inspection.entry.storage_mode == "cas" {
        match inspection.entry.blob_count {
            Some(blob_count) => format!("cas ({blob_count} blobs)"),
            None => "cas".to_string(),
        }
    } else {
        "archive".to_string()
    }
}

fn restore_command(inspection: &CacheInspectResponse) -> String {
    let restore_target = preferred_human_tag(inspection)
        .unwrap_or_else(|| inspection.entry.manifest_root_digest.clone());
    format!(
        "boringcache restore {} {}:/tmp",
        inspection.workspace.slug, restore_target
    )
}

fn save_command(inspection: &CacheInspectResponse) -> String {
    let save_target = preferred_human_tag(inspection).unwrap_or_else(|| "<tag>".to_string());
    format!(
        "boringcache save {} {}:<path>",
        inspection.workspace.slug, save_target
    )
}

fn remove_command(inspection: &CacheInspectResponse) -> Option<String> {
    preferred_human_tag(inspection)
        .map(|tag| format!("boringcache rm {} {}", inspection.workspace.slug, tag))
}

fn preferred_human_tag(inspection: &CacheInspectResponse) -> Option<String> {
    if inspection.identifier.matched_by == "tag" {
        let query = inspection.identifier.query.trim();
        if inspection
            .tags
            .iter()
            .any(|tag| tag.name == query && !tag.system)
        {
            return Some(query.to_string());
        }
    }

    inspection.entry.primary_tag.clone().or_else(|| {
        inspection
            .tags
            .iter()
            .find(|tag| !tag.system)
            .map(|tag| tag.name.clone())
    })
}

fn print_field(label: &str, value: &str) {
    println!("  {:<13} {}", label, value);
}

fn format_relative_time(timestamp: Option<&str>) -> String {
    let Some(timestamp) = timestamp else {
        return "-".to_string();
    };

    if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
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
        timestamp.to_string()
    }
}

fn format_millis(value: f64) -> String {
    if value <= 0.0 {
        "-".to_string()
    } else {
        format!("{value:.0} ms")
    }
}

fn parse_inspect_args(
    workspace_or_identifier: String,
    identifier: Option<String>,
) -> Result<(Option<String>, String)> {
    let first = workspace_or_identifier.trim().to_string();
    let second = identifier.map(|value| value.trim().to_string());

    match second {
        Some(target) if target.is_empty() => Err(anyhow!(
            "Inspect target is missing. Run `boringcache inspect <tag|id>` or `boringcache inspect <workspace> <tag|id>`."
        )),
        Some(target) => Ok((Some(first), target)),
        None if first.contains('/') => Err(anyhow!(
            "Inspect target is missing. Run `boringcache inspect <tag|id>` or `boringcache inspect <workspace> <tag|id>`."
        )),
        None => Ok((None, first)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::cache::{
        CacheInspectEntry, CacheInspectIdentifier, CacheInspectPerformance, CacheInspectResponse,
        CacheInspectTag, CacheInspectVersions, CacheInspectWorkspace,
    };

    #[test]
    fn parse_inspect_args_accepts_default_workspace_mode() {
        let (workspace, identifier) =
            parse_inspect_args("ruby-deps".to_string(), None).expect("args should parse");
        assert_eq!(workspace, None);
        assert_eq!(identifier, "ruby-deps");
    }

    #[test]
    fn parse_inspect_args_accepts_explicit_workspace_mode() {
        let (workspace, identifier) = parse_inspect_args(
            "boringcache/rails".to_string(),
            Some("ruby-deps".to_string()),
        )
        .expect("args should parse");
        assert_eq!(workspace.as_deref(), Some("boringcache/rails"));
        assert_eq!(identifier, "ruby-deps");
    }

    #[test]
    fn parse_inspect_args_rejects_workspace_without_target() {
        let error = parse_inspect_args("boringcache/rails".to_string(), None).unwrap_err();
        assert!(error.to_string().contains("Inspect target is missing"));
    }

    #[test]
    fn inspect_json_contract_adds_schema_version() {
        let inspection = CacheInspectResponse {
            workspace: CacheInspectWorkspace {
                name: "Demo".to_string(),
                slug: "org/demo".to_string(),
            },
            identifier: CacheInspectIdentifier {
                query: "ruby-deps".to_string(),
                matched_by: "tag".to_string(),
            },
            entry: CacheInspectEntry {
                id: "entry-1".to_string(),
                primary_tag: Some("ruby-deps".to_string()),
                status: "ready".to_string(),
                manifest_root_digest: "sha256:abc".to_string(),
                manifest_digest: Some("sha256:def".to_string()),
                manifest_format_version: Some(2),
                storage_mode: "archive".to_string(),
                stored_size_bytes: 1024,
                uncompressed_size: Some(2048),
                compressed_size: Some(1024),
                archive_size: Some(1024),
                file_count: Some(12),
                compression_algorithm: Some("zstd".to_string()),
                blob_count: None,
                blob_total_size_bytes: None,
                cas_layout: None,
                storage_verified: true,
                hit_count: 8,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                uploaded_at: Some("2026-04-15T00:00:00Z".to_string()),
                last_accessed_at: Some("2026-04-15T00:00:00Z".to_string()),
                expires_at: None,
                encrypted: false,
                encryption_algorithm: None,
                encryption_recipient_hint: None,
                server_signed: true,
                server_signed_at: Some("2026-04-15T00:00:00Z".to_string()),
            },
            tags: vec![CacheInspectTag {
                name: "ruby-deps".to_string(),
                primary: true,
                system: false,
                created_at: "2026-04-15T00:00:00Z".to_string(),
                updated_at: "2026-04-15T00:00:00Z".to_string(),
            }],
            versions: Some(CacheInspectVersions {
                tag: "ruby-deps".to_string(),
                version_count: 2,
                max_versions: 5,
                current: true,
                total_storage_bytes: 4096,
            }),
            performance: Some(CacheInspectPerformance {
                total_operations: 10,
                saves: 2,
                restores: 8,
                avg_restore_ms: 120.0,
                avg_save_ms: 240.0,
                errors: 0,
                avg_download_speed: 100.0,
                avg_upload_speed: 50.0,
                last_operation: Some("2026-04-15T00:00:00Z".to_string()),
                error_rate: 0.0,
            }),
        };

        let value = crate::json_output::to_value(&inspection).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["workspace"]["slug"], "org/demo");
        assert_eq!(value["entry"]["id"], "entry-1");
    }
}

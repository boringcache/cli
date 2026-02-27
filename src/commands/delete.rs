use anyhow::{anyhow, Result};
use std::time::Instant;

use crate::api::ApiClient;
use crate::cas_oci::sha256_hex;
use crate::progress::{Summary, System as ProgressSystem};
use crate::ui;

pub(crate) fn proxy_internal_root_tag(human_tag: &str) -> String {
    format!("bc_registry_root_v2_{}", sha256_hex(human_tag.as_bytes()))
}

pub async fn execute(
    workspace_option: Option<String>,
    tag: String,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    crate::api::parse_workspace_slug(&workspace)?;
    let api_client = ApiClient::new()?;
    let platform = if no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };
    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();
    let git_context = if git_enabled {
        crate::git::GitContext::detect_with_path(None)
    } else {
        crate::git::GitContext::default()
    };
    let tag_resolver = crate::tag_utils::TagResolver::new(platform, git_context, git_enabled);
    let platform_tag = tag_resolver.effective_save_tag(&tag)?;

    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    let session_id = format!("delete:{}:{}", workspace, platform_tag);
    let title = format!("Deleting cache [{}]", platform_tag);
    let session_start = Instant::now();

    reporter.session_start(session_id.clone(), title, 2)?;

    let step_start = Instant::now();
    reporter.step_start(session_id.clone(), 1, "Validating tag".to_string(), None)?;
    crate::tag_utils::validate_tag(&tag)?;
    reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

    let step_start = Instant::now();
    reporter.step_start(
        session_id.clone(),
        2,
        "Deleting from server".to_string(),
        None,
    )?;

    let proxy_root_tag = proxy_internal_root_tag(&platform_tag);
    let tags_to_delete = vec![platform_tag.clone(), proxy_root_tag.clone()];

    let delete_result = api_client.delete(&workspace, &tags_to_delete).await;

    match delete_result {
        Ok(results) => {
            reporter.step_complete(session_id.clone(), 2, step_start.elapsed())?;

            let response = results
                .iter()
                .find(|item| item.tag == platform_tag)
                .ok_or_else(|| {
                    anyhow!(
                        "Server did not return a response for tag '{}'. This is unexpected.",
                        platform_tag
                    )
                })?;

            let proxy_deleted = results
                .iter()
                .any(|item| item.tag == proxy_root_tag && item.status == "deleted");

            match response.status.as_str() {
                "deleted" => {
                    let summary = Summary {
                        size_bytes: 0,
                        file_count: 1,
                        digest: None,
                        path: None,
                    };

                    reporter.session_complete(session_id, session_start.elapsed(), summary)?;
                    drop(reporter);
                    progress_system.shutdown()?;

                    if proxy_deleted {
                        ui::info("Cache entry and proxy data deleted");
                    } else if verbose {
                        ui::info("Background cleanup scheduled for storage objects");
                    } else {
                        ui::info("Cache entry deleted");
                    }
                    Ok(())
                }
                "missing" => {
                    drop(reporter);
                    progress_system.shutdown()?;

                    if proxy_deleted {
                        ui::info("Proxy data deleted");
                    } else {
                        ui::warn(&format!("No cache entry found for tag: {}", platform_tag));
                        if verbose {
                            if let Some(error) = &response.error {
                                ui::info(error);
                            }
                        }
                    }
                    Ok(())
                }
                _ => {
                    drop(reporter);
                    progress_system.shutdown()?;

                    let message = response
                        .error
                        .clone()
                        .unwrap_or_else(|| "Unknown error while deleting cache".to_string());
                    Err(anyhow!(message))
                }
            }
        }
        Err(err) => {
            reporter.session_error(session_id, err.to_string())?;
            drop(reporter);
            progress_system.shutdown()?;
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_root_tag_matches_serve_derivation() {
        let tag = "grpc-bazel-remote-cache-ubuntu-24-x86_64";
        let root = proxy_internal_root_tag(tag);
        assert!(root.starts_with("bc_registry_root_v2_"));
        assert_eq!(root.len(), "bc_registry_root_v2_".len() + 64);
    }

    #[test]
    fn proxy_root_tag_is_deterministic() {
        let a = proxy_internal_root_tag("my-cache-tag");
        let b = proxy_internal_root_tag("my-cache-tag");
        assert_eq!(a, b);
    }

    #[test]
    fn proxy_root_tag_differs_for_different_human_tags() {
        let a = proxy_internal_root_tag("tag-a");
        let b = proxy_internal_root_tag("tag-b");
        assert_ne!(a, b);
    }

    #[test]
    fn proxy_root_tag_matches_serve_internal_root_tag() {
        let tags = [
            "grpc-bazel-remote-cache",
            "sccache-rust1.89",
            "nx-main-ubuntu-24-x86_64",
        ];
        for tag in tags {
            assert_eq!(
                proxy_internal_root_tag(tag),
                crate::commands::serve::internal_registry_root_tag(tag),
                "delete and serve must derive identical internal root tags for '{tag}'"
            );
        }
    }
}

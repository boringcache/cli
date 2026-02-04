use anyhow::{anyhow, Result};
use std::time::Instant;

use crate::api::ApiClient;
use crate::progress::{Summary, System as ProgressSystem};
use crate::ui;

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

    let delete_result = api_client
        .delete(&workspace, std::slice::from_ref(&platform_tag))
        .await;

    match delete_result {
        Ok(mut results) => {
            reporter.step_complete(session_id.clone(), 2, step_start.elapsed())?;

            let response = results
                .drain(..)
                .find(|item| item.tag == platform_tag)
                .ok_or_else(|| {
                    anyhow!(
                        "Server did not return a response for tag '{}'. This is unexpected.",
                        platform_tag
                    )
                })?;

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

                    if verbose {
                        ui::info("Background cleanup scheduled for storage objects");
                    } else {
                        ui::info("Cache entry deleted");
                    }
                    Ok(())
                }
                "missing" => {
                    drop(reporter);
                    progress_system.shutdown()?;

                    ui::warn(&format!("No cache entry found for tag: {}", platform_tag));
                    if verbose {
                        if let Some(error) = response.error {
                            ui::info(&error);
                        }
                    }
                    Ok(())
                }
                _ => {
                    drop(reporter);
                    progress_system.shutdown()?;

                    let message = response
                        .error
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

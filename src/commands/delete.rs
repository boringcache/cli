use anyhow::Result;
use std::time::Instant;

use crate::api::ApiClient;
use crate::progress::{Summary, System as ProgressSystem};

pub async fn execute(
    workspace_option: Option<String>,
    tag: String,
    verbose: bool,
    no_platform: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let api_client = ApiClient::new()?;

    // Apply platform suffix to tag using centralized utility
    let platform_tag = crate::tag_utils::apply_platform_to_tag(&tag, no_platform)?;

    // Set up progress system
    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    let session_id = format!("delete:{}:{}", workspace, platform_tag);
    let title = format!("Deleting cache [{}]", platform_tag);
    let session_start = Instant::now();

    // Start session with 2 steps: [1/2] Validating, [2/2] Deleting
    reporter.session_start(session_id.clone(), title, 2)?;

    // Step 1: Validating tag
    let step_start = Instant::now();
    reporter.step_start(session_id.clone(), 1, "Validating tag".to_string(), None)?;

    // Validate tag format
    crate::tag_utils::validate_tag_basic(&tag)?;

    reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

    // Step 2: Deleting from server
    let step_start = Instant::now();
    reporter.step_start(
        session_id.clone(),
        2,
        "Deleting from server".to_string(),
        None,
    )?;

    match api_client.delete_cache(&workspace, &platform_tag).await {
        Ok(_) => {
            reporter.step_complete(session_id.clone(), 2, step_start.elapsed())?;

            let summary = Summary {
                size_bytes: 0, // We don't know the size of deleted cache
                file_count: 1, // Represent as 1 cache entry deleted
                digest: None,
                path: None,
            };

            reporter.session_complete(session_id, session_start.elapsed(), summary)?;

            progress_system.shutdown()?;

            // Show cleanup info after progress system shutdown
            if verbose {
                println!("info: Background cleanup will remove storage objects");
                println!("info: This may take a few minutes to complete");
            } else {
                println!("info: Storage cleanup enqueued for background processing");
            }
            Ok(())
        }
        Err(e) => {
            if e.to_string().contains("Cache miss") || e.to_string().contains("404") {
                reporter.session_complete(
                    session_id,
                    session_start.elapsed(),
                    Summary {
                        size_bytes: 0,
                        file_count: 0,
                        digest: None,
                        path: None,
                    },
                )?;

                progress_system.shutdown()?;

                println!("warning: No cache entries found with tag: {}", platform_tag);
                if verbose {
                    println!("info: This tag may have been previously deleted or never existed");
                }
                Ok(())
            } else {
                reporter.session_error(session_id, e.to_string())?;
                progress_system.shutdown()?;
                Err(e)
            }
        }
    }
}

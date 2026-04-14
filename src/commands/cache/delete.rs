use anyhow::{Result, anyhow};
use std::time::Instant;

use crate::api::ApiClient;
use crate::progress::{Summary, System as ProgressSystem};
use crate::ui;

pub async fn execute(
    workspace_or_tag: String,
    tags: Option<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
) -> Result<()> {
    let (workspace_option, tag_list) = parse_delete_args(workspace_or_tag, tags)?;
    let api_client = ApiClient::for_admin()?;
    let workspace = crate::command_support::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache rm <workspace> <tag>",
    )
    .await?;
    crate::api::parse_workspace_slug(&workspace)?;
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
    for tag in tag_list {
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

        let proxy_root_tag = crate::proxy::internal_registry_root_tag(&platform_tag);
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
                    }
                    "missing" => {
                        drop(reporter);
                        progress_system.shutdown()?;

                        if proxy_deleted {
                            ui::info("Proxy data deleted");
                        } else {
                            ui::warn(&format!("No cache entry found for tag: {}", platform_tag));
                            if verbose && let Some(error) = &response.error {
                                ui::info(error);
                            }
                        }
                    }
                    _ => {
                        drop(reporter);
                        progress_system.shutdown()?;

                        let message = response
                            .error
                            .clone()
                            .unwrap_or_else(|| "Unknown error while deleting cache".to_string());
                        return Err(anyhow!(message));
                    }
                }
            }
            Err(err) => {
                reporter.session_error(session_id, err.to_string())?;
                drop(reporter);
                progress_system.shutdown()?;
                return Err(err);
            }
        }
    }

    Ok(())
}

fn parse_delete_args(
    workspace_or_tag: String,
    tags: Option<String>,
) -> Result<(Option<String>, Vec<String>)> {
    let first = workspace_or_tag.trim().to_string();
    let second = tags.map(|value| value.trim().to_string());

    let (workspace, raw_tags) = match second {
        Some(tag_list) if tag_list.is_empty() => {
            return Err(anyhow!(
                "Delete target is missing. Run `boringcache rm <tag>` or `boringcache rm <workspace> <tag>`."
            ));
        }
        Some(tag_list) => (Some(first), tag_list),
        None => (None, first),
    };

    let parsed_tags = raw_tags
        .split(',')
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect::<Vec<_>>();

    if parsed_tags.is_empty() {
        return Err(anyhow!(
            "Delete target is missing. Run `boringcache rm <tag>` or `boringcache rm <workspace> <tag>`."
        ));
    }

    Ok((workspace, parsed_tags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_root_tag_matches_serve_derivation() {
        let tag = "grpc-bazel-remote-cache-ubuntu-24-x86_64";
        let root = crate::proxy::internal_registry_root_tag(tag);
        assert!(root.starts_with("bc_registry_root_v2_"));
        assert_eq!(root.len(), "bc_registry_root_v2_".len() + 64);
    }

    #[test]
    fn proxy_root_tag_is_deterministic() {
        let a = crate::proxy::internal_registry_root_tag("my-cache-tag");
        let b = crate::proxy::internal_registry_root_tag("my-cache-tag");
        assert_eq!(a, b);
    }

    #[test]
    fn proxy_root_tag_differs_for_different_human_tags() {
        let a = crate::proxy::internal_registry_root_tag("tag-a");
        let b = crate::proxy::internal_registry_root_tag("tag-b");
        assert_ne!(a, b);
    }

    #[test]
    fn parse_delete_args_accepts_default_workspace_mode() {
        let (workspace, tags) =
            parse_delete_args("ruby-deps".to_string(), None).expect("args should parse");
        assert_eq!(workspace, None);
        assert_eq!(tags, vec!["ruby-deps"]);
    }

    #[test]
    fn parse_delete_args_accepts_single_tag_with_slash() {
        let (workspace, tags) =
            parse_delete_args("org/tag-name".to_string(), None).expect("args should parse");
        assert_eq!(workspace, None);
        assert_eq!(tags, vec!["org/tag-name"]);
    }

    #[test]
    fn parse_delete_args_accepts_explicit_workspace_mode() {
        let (workspace, tags) = parse_delete_args(
            "boringcache/rails".to_string(),
            Some("ruby-deps, gems".to_string()),
        )
        .expect("args should parse");
        assert_eq!(workspace.as_deref(), Some("boringcache/rails"));
        assert_eq!(tags, vec!["ruby-deps", "gems"]);
    }
}

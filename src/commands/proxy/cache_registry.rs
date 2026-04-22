use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::api::client::ApiClient;
use crate::config::{AuthPurpose, Config};
use crate::git::GitContext;
use crate::tag_utils::TagResolver;
use crate::ui;

const PROXY_METADATA_HINTS_ENV: &str = "BORINGCACHE_PROXY_METADATA_HINTS";
const MAX_PROXY_METADATA_HINTS: usize = 8;
const MAX_PROXY_METADATA_HINT_KEY_BYTES: usize = 32;
const MAX_PROXY_METADATA_HINT_VALUE_BYTES: usize = 64;
#[cfg(test)]
const PROXY_STATUS_PATH: &str = "/_boringcache/status";
#[cfg(test)]
const PROXY_PHASE_HEADER: &str = "X-BoringCache-Proxy-Phase";
#[cfg(test)]
const PROXY_READY_PHASE: &str = "ready";
const PROXY_READY_TIMEOUT: Duration = Duration::from_secs(330);
const PROXY_READY_POLL_INTERVAL: Duration = Duration::from_millis(200);
const PROXY_READY_WARN_INTERVAL: Duration = Duration::from_secs(15);

pub struct ProxyServerHandle {
    handle: crate::serve::ServeHandle,
    endpoint_host: String,
    port: u16,
    primary_human_tag: String,
}

impl ProxyServerHandle {
    pub fn endpoint_host(&self) -> &str {
        &self.endpoint_host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn cache_ref(&self) -> String {
        format!(
            "{}:{}/cache:{}",
            self.endpoint_host, self.port, self.primary_human_tag
        )
    }

    pub async fn shutdown_and_flush(self) -> Result<()> {
        self.handle.shutdown_and_flush().await
    }

    async fn wait_until_ready(&self) -> Result<()> {
        let started_at = tokio::time::Instant::now();
        let deadline = started_at + PROXY_READY_TIMEOUT;
        let mut next_warn_at = started_at + PROXY_READY_WARN_INTERVAL;

        loop {
            if self.handle.is_ready() {
                return Ok(());
            }

            if let Some(message) = self.handle.prefetch_error_message().await {
                anyhow::bail!("Cache registry warmup failed: {message}");
            }

            if self.handle.is_finished() {
                anyhow::bail!("Cache registry exited before readiness");
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                anyhow::bail!(
                    "Timed out waiting for cache-registry readiness after {}s",
                    PROXY_READY_TIMEOUT.as_secs()
                );
            }

            if now >= next_warn_at {
                ui::info(&format!(
                    "[boringcache] Waiting for cache-registry readiness... ({}s)",
                    started_at.elapsed().as_secs()
                ));
                next_warn_at += PROXY_READY_WARN_INTERVAL;
            }

            let notified = self.handle.ready_notification();
            if self.handle.is_ready() {
                return Ok(());
            }

            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(PROXY_READY_POLL_INTERVAL) => {}
            }
        }
    }
}

pub(crate) fn planned_cache_ref(
    tag: &str,
    endpoint_host: &str,
    port: u16,
    no_platform: bool,
    no_git: bool,
) -> Result<String> {
    let tag_resolver = build_tag_resolver(no_platform, no_git)?;
    let (_, configured_human_tags) = resolve_registry_tag_config(&tag_resolver, tag)?;
    Ok(format!(
        "{}:{}/cache:{}",
        endpoint_host, port, configured_human_tags[0]
    ))
}

pub(crate) fn effective_proxy_read_only(explicit_read_only: bool) -> bool {
    if explicit_read_only {
        return true;
    }

    let has_save_auth = Config::load_for_auth_purpose(AuthPurpose::Save).is_ok();
    if has_save_auth {
        return false;
    }

    Config::load_for_auth_purpose(AuthPurpose::Restore).is_ok()
}

pub(crate) fn proxy_startup_mode(startup_warm: bool) -> &'static str {
    if startup_warm { "warm" } else { "on-demand" }
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    workspace: String,
    tag: String,
    host: String,
    port: u16,
    no_platform: bool,
    no_git: bool,
    oci_prefetch_ref: Vec<String>,
    oci_hydration: String,
    metadata_hints: Vec<String>,
    startup_warm: bool,
    ready_file: Option<String>,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<()> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    if std::env::var("BORINGCACHE_TEST_MODE").as_deref() == Ok("1") {
        return Ok(());
    }

    let api_client = if read_only {
        ApiClient::for_restore()?
    } else {
        ApiClient::for_save()?
    };
    let tag_resolver = build_tag_resolver(no_platform, no_git)?;
    let (registry_root_tag, configured_human_tags) =
        resolve_registry_tag_config(&tag_resolver, &tag)?;
    let oci_prefetch_refs = resolve_oci_prefetch_refs(&oci_prefetch_ref)?;
    let oci_hydration_policy = resolve_oci_hydration_policy(&oci_hydration)?;
    let proxy_metadata_hints = resolve_proxy_metadata_hints(&metadata_hints)?;

    crate::serve::run_server(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        Vec::new(),
        proxy_metadata_hints,
        startup_warm,
        oci_prefetch_refs,
        oci_hydration_policy,
        fail_on_cache_error,
        read_only,
        ready_file.map(PathBuf::from),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn start_proxy_background(
    workspace: String,
    tag: String,
    host: String,
    port: u16,
    no_platform: bool,
    no_git: bool,
    oci_prefetch_refs: Vec<(String, String)>,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
    endpoint_host_override: Option<String>,
    proxy_metadata_hints: BTreeMap<String, String>,
    startup_warm: bool,
    fail_on_cache_error: bool,
    read_only: bool,
    oci_alias_promotion_refs: Vec<String>,
) -> Result<ProxyServerHandle> {
    ensure!(
        workspace.contains('/'),
        "Workspace must be in org/project format"
    );

    let api_client = if read_only {
        ApiClient::for_restore()?
    } else {
        ApiClient::for_save()?
    };
    let tag_resolver = build_tag_resolver(no_platform, no_git)?;
    let (registry_root_tag, configured_human_tags) =
        resolve_registry_tag_config(&tag_resolver, &tag)?;

    let primary_human_tag = configured_human_tags[0].clone();
    let endpoint_host = endpoint_host_override
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if host == "0.0.0.0" {
                "127.0.0.1".to_string()
            } else {
                host.clone()
            }
        });

    let handle = crate::serve::start_server_background(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        oci_alias_promotion_refs,
        proxy_metadata_hints,
        startup_warm,
        oci_prefetch_refs,
        oci_hydration_policy,
        fail_on_cache_error,
        read_only,
    )
    .await?;

    let proxy_handle = ProxyServerHandle {
        port: handle.port,
        handle,
        endpoint_host,
        primary_human_tag,
    };

    if let Err(error) = proxy_handle.wait_until_ready().await {
        return match proxy_handle.shutdown_and_flush().await {
            Ok(()) => Err(error),
            Err(shutdown_error) => Err(error.context(format!(
                "Failed to stop cache-registry after readiness failure: {shutdown_error:#}"
            ))),
        };
    }

    Ok(proxy_handle)
}

fn resolve_registry_tag_config(
    tag_resolver: &TagResolver,
    raw_tags: &str,
) -> Result<(String, Vec<String>)> {
    let mut resolved_tags = Vec::new();
    for raw in raw_tags
        .split(',')
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        let resolved = tag_resolver.effective_save_tag(raw)?;
        if !resolved_tags.contains(&resolved) {
            resolved_tags.push(resolved);
        }
    }
    ensure!(!resolved_tags.is_empty(), "Tag must not be empty");

    let registry_root_tag = crate::proxy::internal_registry_root_tag(&resolved_tags[0]);
    let configured_human_tags = resolved_tags;

    Ok((registry_root_tag, configured_human_tags))
}

pub(crate) fn resolve_oci_prefetch_refs(
    oci_prefetch_ref: &[String],
) -> Result<Vec<(String, String)>> {
    let mut refs = Vec::new();
    let mut seen = BTreeSet::<(String, String)>::new();

    for raw in oci_prefetch_ref {
        let trimmed = raw.trim();
        let (name, reference) = parse_oci_prefetch_ref(trimmed).context(format!(
            "Invalid OCI prefetch ref format for {trimmed}, expected NAME@REFERENCE"
        ))?;
        if seen.insert((name.clone(), reference.clone())) {
            refs.push((name, reference));
        }
    }

    Ok(refs)
}

pub(crate) fn resolve_oci_hydration_policy(
    value: &str,
) -> Result<crate::serve::OciHydrationPolicy> {
    crate::serve::OciHydrationPolicy::parse(value)
}

fn parse_oci_prefetch_ref(raw: &str) -> Result<(String, String)> {
    let (name, reference) = raw
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("missing '@' separator"))?;
    let name = name.trim();
    let reference = reference.trim();
    ensure!(!name.is_empty(), "repository name is empty");
    ensure!(!reference.is_empty(), "reference is empty");
    Ok((name.to_string(), reference.to_string()))
}

fn build_tag_resolver(no_platform: bool, no_git: bool) -> Result<TagResolver> {
    let platform = if no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };
    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();
    let git_context = if git_enabled {
        GitContext::detect()
    } else {
        GitContext::default()
    };
    Ok(TagResolver::new(platform, git_context, git_enabled))
}

#[cfg(test)]
fn proxy_status_url(host: &str, port: u16) -> String {
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("http://{authority}:{port}{PROXY_STATUS_PATH}")
}

pub(crate) fn resolve_proxy_metadata_hints(
    raw_hints: &[String],
) -> Result<BTreeMap<String, String>> {
    let mut hints = BTreeMap::new();

    if let Some(env_hints) = crate::config::env_var(PROXY_METADATA_HINTS_ENV) {
        let parts = env_hints
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        merge_proxy_metadata_hints(&mut hints, &parts, PROXY_METADATA_HINTS_ENV)?;
    }

    merge_proxy_metadata_hints(&mut hints, raw_hints, "command line")?;
    Ok(hints)
}

fn merge_proxy_metadata_hints(
    hints: &mut BTreeMap<String, String>,
    raw_hints: &[String],
    source: &str,
) -> Result<()> {
    for raw_hint in raw_hints {
        let trimmed = raw_hint.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = parse_proxy_metadata_hint(trimmed, source)?;
        hints.insert(key, value);
        ensure!(
            hints.len() <= MAX_PROXY_METADATA_HINTS,
            "Proxy metadata hints support up to {MAX_PROXY_METADATA_HINTS} unique keys"
        );
    }

    Ok(())
}

fn parse_proxy_metadata_hint(raw_hint: &str, source: &str) -> Result<(String, String)> {
    let (raw_key, raw_value) = raw_hint
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("Invalid proxy metadata hint in {source}: {raw_hint}"))?;

    let key = normalize_proxy_metadata_hint_key(raw_key).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid proxy metadata hint key in {source}: {raw_key} (expected lowercase letters, digits, underscores, or hyphens)"
        )
    })?;
    let value = normalize_proxy_metadata_hint_value(raw_value).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid proxy metadata hint value in {source}: {raw_value} (use short ASCII labels like zed, grpc, warm, or changed-source)"
        )
    })?;

    Ok((key, value))
}

pub(crate) fn normalize_proxy_metadata_hint(
    raw_key: &str,
    raw_value: &str,
) -> Option<(String, String)> {
    let key = normalize_proxy_metadata_hint_key(raw_key)?;
    let value = normalize_proxy_metadata_hint_value(raw_value)?;
    Some((key, value))
}

pub(crate) fn insert_replayable_proxy_metadata_hint(
    hints: &mut BTreeMap<String, String>,
    raw_key: &str,
    raw_value: &str,
) -> bool {
    let Some((key, value)) = normalize_proxy_metadata_hint(raw_key, raw_value) else {
        return false;
    };
    if !hints.contains_key(&key) && hints.len() >= MAX_PROXY_METADATA_HINTS {
        return false;
    }
    hints.insert(key, value);
    true
}

fn normalize_proxy_metadata_hint_key(raw_key: &str) -> Option<String> {
    let normalized = raw_key.trim().to_lowercase().replace('-', "_");
    if normalized.is_empty() || normalized.len() > MAX_PROXY_METADATA_HINT_KEY_BYTES {
        return None;
    }
    normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        .then_some(normalized)
}

fn normalize_proxy_metadata_hint_value(raw_value: &str) -> Option<String> {
    let normalized = raw_value
        .trim()
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_whitespace() { '-' } else { ch })
        .collect::<String>();
    if normalized.is_empty() || normalized.len() > MAX_PROXY_METADATA_HINT_VALUE_BYTES {
        return None;
    }
    normalized
        .chars()
        .all(|ch| {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '_' | '-' | '.' | ':' | '/')
        })
        .then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;
    use axum::Json;
    use axum::Router;
    use axum::routing::get;
    use std::collections::BTreeMap;
    use tokio::sync::oneshot;

    #[test]
    fn root_tag_without_aliases() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let (root, aliases) = resolve_registry_tag_config(&resolver, "registry-root").unwrap();
        assert_eq!(
            root,
            crate::proxy::internal_registry_root_tag("registry-root")
        );
        assert_eq!(aliases, vec!["registry-root".to_string()]);
    }

    #[test]
    fn aliases_include_first_tag_and_deduplicate() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let (root, aliases) = resolve_registry_tag_config(
            &resolver,
            "registry-root,oci-main,registry-root,oci-main,oci-stable",
        )
        .unwrap();

        assert_eq!(
            root,
            crate::proxy::internal_registry_root_tag("registry-root")
        );
        assert_eq!(
            aliases,
            vec![
                "registry-root".to_string(),
                "oci-main".to_string(),
                "oci-stable".to_string()
            ]
        );
    }

    #[test]
    fn empty_tag_string_is_rejected() {
        let resolver = TagResolver::new(None, GitContext::default(), false);
        let error = resolve_registry_tag_config(&resolver, " , ").unwrap_err();
        assert!(error.to_string().contains("Tag must not be empty"));
    }

    #[test]
    fn proxy_metadata_hints_merge_env_and_flags() {
        let _guard = test_env::lock();
        test_env::set_var(PROXY_METADATA_HINTS_ENV, "project=zed,phase=seed");
        let hints =
            resolve_proxy_metadata_hints(&["phase=warm".to_string(), "tooling=main".to_string()])
                .unwrap();
        test_env::remove_var(PROXY_METADATA_HINTS_ENV);

        assert_eq!(
            hints,
            BTreeMap::from([
                ("phase".to_string(), "warm".to_string()),
                ("project".to_string(), "zed".to_string()),
                ("tooling".to_string(), "main".to_string()),
            ])
        );
    }

    #[test]
    fn proxy_metadata_hints_normalize_case_and_spacing() {
        let hints = resolve_proxy_metadata_hints(&[
            "Project=Zed".to_string(),
            "phase=Changed Source".to_string(),
        ])
        .unwrap();

        assert_eq!(hints.get("project"), Some(&"zed".to_string()));
        assert_eq!(hints.get("phase"), Some(&"changed-source".to_string()));
    }

    #[test]
    fn proxy_metadata_hints_reject_invalid_keys() {
        let error = resolve_proxy_metadata_hints(&["bad key=value".to_string()]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Invalid proxy metadata hint key")
        );
    }

    #[test]
    fn resolve_oci_prefetch_refs_deduplicates_and_trims() {
        let refs = resolve_oci_prefetch_refs(&[
            "library/ubuntu  @  latest ".to_string(),
            "library/ubuntu@latest".to_string(),
            "node:20@sha256:abc".to_string(),
        ])
        .unwrap();

        assert_eq!(
            refs,
            vec![
                ("library/ubuntu".to_string(), "latest".to_string()),
                ("node:20".to_string(), "sha256:abc".to_string()),
            ]
        );
    }

    #[test]
    fn resolve_oci_prefetch_refs_rejects_invalid_values() {
        let missing_separator =
            resolve_oci_prefetch_refs(&["library/ubuntu".to_string()]).unwrap_err();
        assert!(
            missing_separator
                .to_string()
                .contains("Invalid OCI prefetch ref format for library/ubuntu")
        );
        assert!(
            resolve_oci_prefetch_refs(&["@sha256:abc".to_string()])
                .unwrap_err()
                .to_string()
                .contains("Invalid OCI prefetch ref format for @sha256:abc")
        );
    }

    #[tokio::test]
    async fn start_proxy_background_waits_for_ready_before_returning() {
        let _guard = test_env::lock();
        let home = tempfile::tempdir().expect("temp home");
        let (api_url, shutdown_api) = start_delayed_cache_api(Duration::from_millis(400)).await;
        let _home_var = set_scoped_env_var("HOME", home.path().to_string_lossy().as_ref());
        let _api_url_var = set_scoped_env_var("BORINGCACHE_API_URL", &api_url);
        let _save_token_var = set_scoped_env_var("BORINGCACHE_SAVE_TOKEN", "test-save-token");
        test_env::remove_var("BORINGCACHE_API_TOKEN");
        test_env::remove_var("BORINGCACHE_TOKEN_FILE");

        let start_task = tokio::spawn(start_proxy_background(
            "org/repo".to_string(),
            "registry-root".to_string(),
            "127.0.0.1".to_string(),
            0,
            true,
            true,
            Vec::new(),
            crate::serve::OciHydrationPolicy::MetadataOnly,
            Some("builder.internal.invalid".to_string()),
            BTreeMap::new(),
            true,
            true,
            false,
            Vec::new(),
        ));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !start_task.is_finished(),
            "background proxy start should wait while warming"
        );

        let proxy_handle = start_task
            .await
            .expect("join proxy start task")
            .expect("start proxy");

        let response = reqwest::Client::new()
            .get(proxy_status_url("127.0.0.1", proxy_handle.port()))
            .send()
            .await
            .expect("fetch proxy status");
        assert_eq!(
            response
                .headers()
                .get(PROXY_PHASE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(PROXY_READY_PHASE)
        );
        assert_eq!(proxy_handle.endpoint_host(), "builder.internal.invalid");

        proxy_handle
            .shutdown_and_flush()
            .await
            .expect("shutdown proxy");
        let _ = shutdown_api.send(());
    }

    #[tokio::test]
    async fn start_proxy_background_on_demand_returns_without_waiting_for_warmup() {
        let _guard = test_env::lock();
        let home = tempfile::tempdir().expect("temp home");
        let (api_url, shutdown_api) = start_delayed_cache_api(Duration::from_secs(5)).await;
        let _home_var = set_scoped_env_var("HOME", home.path().to_string_lossy().as_ref());
        let _api_url_var = set_scoped_env_var("BORINGCACHE_API_URL", &api_url);
        let _save_token_var = set_scoped_env_var("BORINGCACHE_SAVE_TOKEN", "test-save-token");
        test_env::remove_var("BORINGCACHE_API_TOKEN");
        test_env::remove_var("BORINGCACHE_TOKEN_FILE");

        let start_task = tokio::spawn(start_proxy_background(
            "org/repo".to_string(),
            "registry-root".to_string(),
            "127.0.0.1".to_string(),
            0,
            true,
            true,
            Vec::new(),
            crate::serve::OciHydrationPolicy::MetadataOnly,
            None,
            BTreeMap::new(),
            false,
            true,
            false,
            Vec::new(),
        ));

        let proxy_handle = tokio::time::timeout(Duration::from_secs(1), start_task)
            .await
            .expect("on-demand proxy start should not wait for delayed warmup")
            .expect("join proxy start task")
            .expect("start proxy");

        let response = reqwest::Client::new()
            .get(proxy_status_url("127.0.0.1", proxy_handle.port()))
            .send()
            .await
            .expect("fetch proxy status");
        assert_eq!(
            response
                .headers()
                .get(PROXY_PHASE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(PROXY_READY_PHASE)
        );

        proxy_handle
            .shutdown_and_flush()
            .await
            .expect("shutdown proxy");
        let _ = shutdown_api.send(());
    }

    struct ScopedEnvVar(&'static str);

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            test_env::remove_var(self.0);
        }
    }

    fn set_scoped_env_var(key: &'static str, value: &str) -> ScopedEnvVar {
        test_env::set_var(key, value);
        ScopedEnvVar(key)
    }

    async fn start_delayed_cache_api(delay: Duration) -> (String, oneshot::Sender<()>) {
        let app = Router::new().route(
            "/v2/workspaces/{org}/{repo}/caches",
            get({
                move || async move {
                    tokio::time::sleep(delay).await;
                    Json(Vec::<serde_json::Value>::new())
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind delayed api");
        let address = listener.local_addr().expect("delayed api addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve delayed api");
        });

        (format!("http://{address}"), shutdown_tx)
    }
}

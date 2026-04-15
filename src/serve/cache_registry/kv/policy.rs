use super::*;

pub(crate) fn parse_positive_usize_env(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<usize>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}

pub(crate) fn parse_positive_u64_env(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u64>() {
        Ok(value) if value > 0 => Some(value),
        _ => None,
    }
}

fn kv_miss_generation(state: &AppState, registry_root_tag: &str) -> u64 {
    state
        .kv_miss_generations
        .get(registry_root_tag.trim())
        .map(|entry| *entry.value())
        .unwrap_or(0)
}

pub(crate) fn kv_miss_cache_key(
    state: &AppState,
    registry_root_tag: &str,
    scoped_key: &str,
) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        registry_root_tag.trim(),
        kv_miss_generation(state, registry_root_tag),
        scoped_key
    )
}

pub(crate) fn use_kv_miss_cache(namespace: KvNamespace) -> bool {
    !matches!(namespace, KvNamespace::Sccache)
}

pub(crate) fn conflict_backoff_window(message: &str) -> (u64, u64) {
    let lower = message.to_ascii_lowercase();
    if lower.contains("another cache upload is in progress")
        || lower.contains("cache upload in progress")
    {
        (
            KV_CONFLICT_IN_PROGRESS_BACKOFF_MS,
            KV_CONFLICT_IN_PROGRESS_JITTER_MS,
        )
    } else {
        (KV_CONFLICT_BACKOFF_MS, KV_CONFLICT_JITTER_MS)
    }
}

pub(crate) fn transient_backoff_window(message: &str) -> (u64, u64) {
    let lower = message.to_ascii_lowercase();
    if lower.contains("save_entry failed")
        || lower.contains("blob upload failed")
        || lower.contains("confirm failed")
    {
        (
            KV_TRANSIENT_WRITE_PATH_BACKOFF_MS,
            KV_TRANSIENT_WRITE_PATH_JITTER_MS,
        )
    } else {
        (KV_TRANSIENT_BACKOFF_MS, KV_TRANSIENT_JITTER_MS)
    }
}

pub(crate) fn is_blob_verification_pending_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not yet verified in storage") || lower.contains("retry after upload completes")
}

pub(crate) fn kv_confirm_verification_retry_delay(attempt: u32) -> std::time::Duration {
    let exponent = attempt.saturating_sub(1).min(6);
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let delay_ms = KV_CONFIRM_VERIFICATION_RETRY_BASE_MS
        .saturating_mul(multiplier)
        .min(KV_CONFIRM_VERIFICATION_RETRY_MAX_MS);
    std::time::Duration::from_millis(delay_ms)
}

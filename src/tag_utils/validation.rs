use anyhow::Result;

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    Ok(())
}

// Keep this aligned with boringcache/web/app/models/cache_tag.rb#CacheTag.valid_human_name?.
pub fn server_cache_tag_name(tag: &str) -> bool {
    let trimmed = tag.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 512
        && !matches!(trimmed.as_bytes().first(), Some(b'.' | b'-'))
        && !matches!(trimmed.as_bytes().last(), Some(b'.' | b'-'))
        && !trimmed.contains("..")
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

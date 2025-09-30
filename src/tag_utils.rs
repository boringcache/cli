use anyhow::Result;

pub fn validate_tag_basic(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    if tag.contains(' ') {
        anyhow::bail!("Tag '{}' cannot contain spaces", tag);
    }

    if tag.contains(':') || tag.contains('@') {
        anyhow::bail!("Tag '{}' contains invalid characters (:, @)", tag);
    }

    Ok(())
}

/// Apply platform detection and tag transformation logic consistently across all commands
/// Performance optimized: only detects platform once when needed
#[inline]
pub fn apply_platform_to_tag(tag: &str, no_platform: bool) -> anyhow::Result<String> {
    if no_platform {
        Ok(tag.to_string())
    } else {
        let platform = crate::platform::Platform::detect()?;
        Ok(platform.append_to_tag(tag))
    }
}

/// Apply platform suffix logic with optional platform instance (for performance when called multiple times)
/// Performance optimized: avoids redundant platform detection in batch operations
#[inline]
pub fn apply_platform_to_tag_with_instance(
    tag: &str,
    platform_option: Option<&crate::platform::Platform>,
) -> String {
    if let Some(platform) = platform_option {
        platform.append_to_tag(tag)
    } else {
        tag.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tag_validation() {
        assert!(validate_tag_basic("ruby-3.4.4").is_ok());
        assert!(validate_tag_basic("node_18.0.0").is_ok());
        assert!(validate_tag_basic("deps.cache").is_ok());

        assert!(validate_tag_basic("").is_err());
        assert!(validate_tag_basic("tag with spaces").is_err());
        assert!(validate_tag_basic("tag:with:colons").is_err());
        assert!(validate_tag_basic("tag@with@ats").is_err());
    }
}

use anyhow::Result;

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    if tag.len() > 128 {
        anyhow::bail!("Tag '{}' is too long (max 128 characters)", tag);
    }

    let valid_chars = tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');

    if !valid_chars {
        anyhow::bail!(
            "Tag '{}' contains invalid characters. Only alphanumeric characters, dots (.), dashes (-), and underscores (_) are allowed",
            tag
        );
    }

    if tag.starts_with('.') || tag.starts_with('-') {
        anyhow::bail!("Tag '{}' cannot start with '.' or '-'", tag);
    }

    if tag.ends_with('.') || tag.ends_with('-') {
        anyhow::bail!("Tag '{}' cannot end with '.' or '-'", tag);
    }

    if tag.contains("..") {
        anyhow::bail!("Tag '{}' cannot contain consecutive dots (..)", tag);
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
    fn test_tag_validation() {
        assert!(validate_tag("ruby-3.4.4").is_ok());
        assert!(validate_tag("node_18.0.0").is_ok());
        assert!(validate_tag("deps.cache").is_ok());
        assert!(validate_tag("valid-tag_123.test").is_ok());

        assert!(validate_tag("").is_err());
        assert!(validate_tag("tag with spaces").is_err());
        assert!(validate_tag("tag:with:colons").is_err());
        assert!(validate_tag("tag@with@ats").is_err());
        assert!(validate_tag(".starts-with-dot").is_err());
        assert!(validate_tag("-starts-with-dash").is_err());
        assert!(validate_tag("ends-with-dot.").is_err());
        assert!(validate_tag("ends-with-dash-").is_err());
        assert!(validate_tag("has..consecutive..dots").is_err());
        assert!(validate_tag(&"a".repeat(129)).is_err());
    }
}

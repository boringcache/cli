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

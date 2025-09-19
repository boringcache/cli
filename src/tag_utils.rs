use crate::platform::Platform;
use anyhow::Result;

pub struct Tag {
    pub user_tag: String,
    pub platform_tag: String,
}

impl Tag {
    pub fn new(user_tag: &str, platform: &Platform) -> Self {
        let platform_suffix = platform.to_tag_suffix();
        let platform_tag = format!("{}-{}", user_tag, platform_suffix);

        Self {
            user_tag: user_tag.to_string(),
            platform_tag,
        }
    }

    pub fn from_existing(full_tag: &str) -> Self {
        if let Some(last_dash) = full_tag.rfind('-') {
            if let Some(second_last_dash) = full_tag[..last_dash].rfind('-') {
                let potential_platform = &full_tag[second_last_dash + 1..];
                if Platform::is_valid_tag_suffix(potential_platform) {
                    return Self {
                        user_tag: full_tag[..second_last_dash].to_string(),
                        platform_tag: full_tag.to_string(),
                    };
                }
            }
        }

        Self {
            user_tag: full_tag.to_string(),
            platform_tag: full_tag.to_string(),
        }
    }

    pub fn platform_suffix(&self) -> String {
        if self.user_tag == self.platform_tag {
            "-".to_string()
        } else {
            self.platform_tag
                .strip_prefix(&format!("{}-", self.user_tag))
                .unwrap_or("-")
                .to_string()
        }
    }
}

fn validate_tag_basic(tag: &str) -> Result<()> {
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

pub fn ensure_platform_aware_tag(
    tag: &str,
    platform: &Platform,
    no_platform: bool,
) -> Result<String> {
    validate_tag_basic(tag)?;

    Ok(if no_platform {
        tag.to_string()
    } else {
        Tag::new(tag, platform).platform_tag
    })
}

pub fn resolve_tag_for_restore(
    tag: &str,
    platform: &Platform,
    no_platform: bool,
) -> Result<String> {
    validate_tag_basic(tag)?;

    Ok(if no_platform {
        tag.to_string()
    } else {
        let parsed = Tag::from_existing(tag);
        if parsed.user_tag == parsed.platform_tag {
            Tag::new(tag, platform).platform_tag
        } else {
            parsed.platform_tag
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_creation() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x64".to_string(),
            distro: None,
            version: None,
            glibc: None,
        };

        let tag = Tag::new("ruby3.4.4", &platform);
        assert_eq!(tag.user_tag, "ruby3.4.4");
        assert_eq!(tag.platform_tag, "ruby3.4.4-linux-amd64");
    }

    #[test]
    fn test_parse_existing_tag() {
        let tag = Tag::from_existing("ruby3.4.4-darwin-arm64");
        assert_eq!(tag.user_tag, "ruby3.4.4");
        assert_eq!(tag.platform_tag, "ruby3.4.4-darwin-arm64");

        let tag2 = Tag::from_existing("node-20.11.0");
        assert_eq!(tag2.user_tag, "node-20.11.0");
        assert_eq!(tag2.platform_tag, "node-20.11.0");
    }

    #[test]
    fn test_resolve_for_restore() {
        let platform = Platform {
            os: "macos".to_string(),
            arch: "arm64".to_string(),
            distro: None,
            version: None,
            glibc: None,
        };

        let resolved = resolve_tag_for_restore("ruby3.4.4", &platform, false).unwrap();
        assert_eq!(resolved, "ruby3.4.4-macos-arm64");

        let resolved2 = resolve_tag_for_restore("ruby3.4.4-linux-amd64", &platform, false).unwrap();
        assert_eq!(resolved2, "ruby3.4.4-linux-amd64");

        let resolved3 = resolve_tag_for_restore("ruby3.4.4", &platform, true).unwrap();
        assert_eq!(resolved3, "ruby3.4.4");
    }

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

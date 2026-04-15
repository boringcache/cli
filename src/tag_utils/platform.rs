use anyhow::Result;

use crate::platform::Platform;

#[inline]
pub fn apply_platform_to_tag(tag: &str, no_platform: bool) -> Result<String> {
    if no_platform {
        Ok(tag.to_string())
    } else {
        let platform = Platform::detect()?;
        Ok(platform.append_to_tag(tag))
    }
}

#[inline]
pub fn apply_platform_to_tag_with_instance(
    tag: &str,
    platform_option: Option<&Platform>,
) -> String {
    if let Some(platform) = platform_option {
        platform.append_to_tag(tag)
    } else {
        tag.to_string()
    }
}

use anyhow::Result;

pub fn validate_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        anyhow::bail!("Tag cannot be empty");
    }

    Ok(())
}

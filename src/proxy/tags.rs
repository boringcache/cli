use crate::cas_oci::sha256_hex;

pub(crate) fn internal_registry_root_tag(primary_human_tag: &str) -> String {
    format!(
        "bc_registry_root_v2_{}",
        sha256_hex(primary_human_tag.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_registry_root_tag_has_expected_shape() {
        let root = internal_registry_root_tag("registry-root");
        assert!(root.starts_with("bc_registry_root_v2_"));
        assert_eq!(root.len(), "bc_registry_root_v2_".len() + 64);
    }

    #[test]
    fn internal_registry_root_tag_is_deterministic() {
        assert_eq!(
            internal_registry_root_tag("my-cache-tag"),
            internal_registry_root_tag("my-cache-tag")
        );
    }
}

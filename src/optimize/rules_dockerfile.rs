use crate::api::models::optimize::OptimizeChange;

#[derive(Debug, Clone)]
pub struct RuleResult {
    pub optimized_content: String,
    pub changes: Vec<OptimizeChange>,
    pub explanation: String,
}

pub fn apply(content: &str) -> Option<RuleResult> {
    if content.contains("boringcache restore") || content.contains("boringcache save") {
        return None;
    }

    // Deterministic Dockerfile migration is intentionally conservative for now.
    // Most Dockerfile integrations require project-specific cache paths/tags.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_unhandled_dockerfile() {
        let input = "FROM node:20\nRUN npm ci\n";
        assert!(apply(input).is_none());
    }

    #[test]
    fn returns_none_for_already_boringcache_dockerfile() {
        let input = "FROM alpine\nRUN boringcache restore my-org/ws \"deps:/tmp/deps\"\n";
        assert!(apply(input).is_none());
    }
}

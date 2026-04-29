use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub region: Option<String>,

    pub cache_status: Option<String>,

    pub block_location: Option<String>,

    pub timing_header: Option<String>,
}

impl StorageMetrics {
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        let region = headers
            .get("x-tigris-served-from")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let timing_header = headers
            .get("server-timing")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let (cache_status, block_location) = timing_header
            .as_ref()
            .map(|h| Self::parse_server_timing(h))
            .unwrap_or((None, None));

        Self {
            region,
            cache_status,
            block_location,
            timing_header,
        }
    }

    fn parse_server_timing(header: &str) -> (Option<String>, Option<String>) {
        let mut cache_status = None;
        let mut block_location = None;

        for part in header.split(',') {
            let part = part.trim();
            if part.starts_with("cache;") {
                if let Some(desc_start) = part.find("desc=") {
                    let desc_value = &part[desc_start + 5..];
                    let end = desc_value.find(';').unwrap_or(desc_value.len());
                    cache_status = normalize_desc(desc_value, end);
                }
            } else if part.starts_with("block;")
                && let Some(desc_start) = part.find("desc=")
            {
                let desc_value = &part[desc_start + 5..];
                let end = desc_value.find(';').unwrap_or(desc_value.len());
                block_location = normalize_desc(desc_value, end);
            }
        }

        (cache_status, block_location)
    }
}

fn normalize_desc(desc_value: &str, end: usize) -> Option<String> {
    let value = desc_value[..end].trim().trim_matches('"');
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn storage_metrics_parse_region_cache_status_and_block_location() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tigris-served-from", HeaderValue::from_static("iad"));
        headers.insert(
            "server-timing",
            HeaderValue::from_static(
                "total;dur=2750, cache;desc=\"hit\";dur=25, block;desc=remote;dur=2500",
            ),
        );

        let metrics = StorageMetrics::from_headers(&headers);

        assert_eq!(metrics.region.as_deref(), Some("iad"));
        assert_eq!(metrics.cache_status.as_deref(), Some("hit"));
        assert_eq!(metrics.block_location.as_deref(), Some("remote"));
        assert_eq!(
            metrics.timing_header.as_deref(),
            Some("total;dur=2750, cache;desc=\"hit\";dur=25, block;desc=remote;dur=2500")
        );
    }
}

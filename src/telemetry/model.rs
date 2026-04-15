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
                    cache_status = Some(desc_value[..end].to_string());
                }
            } else if part.starts_with("block;")
                && let Some(desc_start) = part.find("desc=")
            {
                let desc_value = &part[desc_start + 5..];
                let end = desc_value.find(';').unwrap_or(desc_value.len());
                block_location = Some(desc_value[..end].to_string());
            }
        }

        (cache_status, block_location)
    }
}

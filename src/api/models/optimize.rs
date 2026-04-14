use super::*;

#[derive(Debug, Serialize)]
pub struct OptimizeFileRequest {
    pub path: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OptimizeRequest {
    pub files: Vec<OptimizeFileRequest>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OptimizeChange {
    pub description: String,
    #[serde(default)]
    pub before_snippet: Option<String>,
    #[serde(default)]
    pub after_snippet: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OptimizeFileResult {
    pub path: String,
    pub status: String,
    #[serde(default)]
    pub detected_type: Option<String>,
    #[serde(default)]
    pub optimized_content: Option<String>,
    #[serde(default)]
    pub changes: Vec<OptimizeChange>,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OptimizeResponse {
    pub results: Vec<OptimizeFileResult>,
}

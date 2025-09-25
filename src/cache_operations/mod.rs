pub mod delete;
pub mod download;
pub mod upload;

use anyhow::Result;

use crate::api::ApiClient;

pub use delete::DeleteOperation;
pub use download::DownloadOperation;
pub use upload::UploadOperation;

#[derive(Clone)]
pub struct CacheOperation {
    pub api_client: ApiClient,
    pub workspace: String,
    pub verbose: bool,
}

impl CacheOperation {
    pub fn new(workspace: String, verbose: bool) -> Result<Self> {
        let api_client = ApiClient::new(None)?;
        Ok(Self {
            api_client,
            workspace,
            verbose,
        })
    }
}

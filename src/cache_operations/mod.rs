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

    pub async fn download_and_extract(
        &self,
        download_url: &str,
        target_path: &str,
        expected_size: u64,
        compression: Option<&str>,
        expected_content_hash: Option<&str>,
    ) -> Result<()> {
        let download_op = DownloadOperation::new(
            self.api_client.clone(),
            self.workspace.clone(),
            self.verbose,
        );

        download_op
            .download_and_extract(
                download_url,
                target_path,
                expected_size,
                compression,
                expected_content_hash,
            )
            .await
    }
}

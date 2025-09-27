pub mod delete;
pub mod download;
pub mod upload;

use anyhow::Result;

use crate::api::ApiClient;

pub use delete::DeleteOperation;
pub use download::{DownloadOperation, DownloadedArchive};
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

    pub async fn download(
        &self,
        download_url: &str,
        expected_size: u64,
        expected_content_hash: Option<&str>,
        progress: Option<std::sync::Arc<crate::commands::utils::TransferProgress>>,
    ) -> Result<DownloadedArchive> {
        let download_op = DownloadOperation::new(
            self.api_client.clone(),
            self.workspace.clone(),
            self.verbose,
        );

        download_op
            .download(download_url, expected_size, expected_content_hash, progress)
            .await
    }

    pub async fn extract(
        &self,
        data: Vec<u8>,
        target_path: &str,
        compression: Option<&str>,
    ) -> Result<std::time::Duration> {
        let download_op = DownloadOperation::new(
            self.api_client.clone(),
            self.workspace.clone(),
            self.verbose,
        );

        download_op.extract(data, target_path, compression).await
    }
}

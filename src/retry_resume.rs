use crate::ui;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;

pub const MAX_RETRIES: u32 = 3;
pub const MAX_BACKOFF_SECS: u64 = 8;

pub struct RetryConfig {
    pub max_retries: u32,
    pub max_backoff_secs: u64,
    pub verbose: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: MAX_RETRIES,
            max_backoff_secs: MAX_BACKOFF_SECS,
            verbose: false,
        }
    }
}

impl RetryConfig {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            ..Default::default()
        }
    }

    pub async fn retry_with_backoff<T, F, Fut>(
        &self,
        operation_name: &str,
        mut operation: F,
    ) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempts = 0;

        loop {
            attempts += 1;

            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if crate::error::is_connection_error(&e) {
                        return Err(e);
                    }

                    if attempts < self.max_retries {
                        if self.verbose {
                            ui::info(&format!(
                                "{} failed, retrying... ({}/{}): {}",
                                operation_name, attempts, self.max_retries, e
                            ));
                        }
                        let delay = std::cmp::min(2_u64.pow(attempts - 1), self.max_backoff_secs);
                        sleep(Duration::from_secs(delay)).await;
                        continue;
                    } else {
                        return Err(anyhow::anyhow!(
                            "{} failed after {} attempts: {}",
                            operation_name,
                            self.max_retries,
                            e
                        ));
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeInfo {
    pub file_path: PathBuf,
    pub total_size: u64,
    pub downloaded_size: u64,
    pub chunks_completed: Vec<bool>,
    pub chunk_size: Option<u64>,
}

impl ResumeInfo {
    pub fn new(file_path: PathBuf, total_size: u64, chunk_count: usize) -> Self {
        Self {
            file_path,
            total_size,
            downloaded_size: 0,
            chunks_completed: vec![false; chunk_count],
            chunk_size: None,
        }
    }

    pub fn new_with_chunk_size(
        file_path: PathBuf,
        total_size: u64,
        chunk_count: usize,
        chunk_size: u64,
    ) -> Self {
        Self {
            file_path,
            total_size,
            downloaded_size: 0,
            chunks_completed: vec![false; chunk_count],
            chunk_size: Some(chunk_size),
        }
    }

    pub fn resume_file_path(&self) -> PathBuf {
        self.file_path.with_extension("boringcache-resume")
    }

    pub async fn save(&self) -> Result<()> {
        let resume_data = serde_json::to_string_pretty(self)?;
        tokio::fs::write(self.resume_file_path(), resume_data).await?;
        Ok(())
    }

    pub async fn load(file_path: &Path) -> Option<Self> {
        let resume_path = file_path.with_extension("boringcache-resume");
        if let Ok(resume_data) = tokio::fs::read_to_string(&resume_path).await {
            serde_json::from_str(&resume_data).ok()
        } else {
            None
        }
    }

    pub fn cleanup(&self) -> Result<()> {
        let resume_path = self.resume_file_path();
        if resume_path.exists() {
            std::fs::remove_file(resume_path)?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.chunks_completed.iter().all(|&completed| completed)
    }

    pub fn progress_percentage(&self) -> f64 {
        if self.total_size == 0 {
            return 100.0;
        }
        (self.downloaded_size as f64 / self.total_size as f64) * 100.0
    }

    pub fn next_incomplete_chunk(&self) -> Option<usize> {
        self.chunks_completed
            .iter()
            .position(|&completed| !completed)
    }

    pub fn mark_chunk_complete(&mut self, chunk_index: usize, chunk_size: u64) {
        if chunk_index < self.chunks_completed.len() && !self.chunks_completed[chunk_index] {
            self.chunks_completed[chunk_index] = true;
            self.downloaded_size += chunk_size;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResumeInfo {
    pub file_path: PathBuf,
    pub upload_id: String,
    pub total_size: u64,
    pub uploaded_parts: Vec<bool>,
    pub part_etags: Vec<Option<String>>,
}

impl UploadResumeInfo {
    pub fn new(file_path: PathBuf, upload_id: String, total_size: u64, part_count: usize) -> Self {
        Self {
            file_path,
            upload_id,
            total_size,
            uploaded_parts: vec![false; part_count],
            part_etags: vec![None; part_count],
        }
    }

    pub fn resume_file_path(&self) -> PathBuf {
        self.file_path.with_extension("boringcache-upload-resume")
    }

    pub async fn save(&self) -> Result<()> {
        let resume_data = serde_json::to_string_pretty(self)?;
        tokio::fs::write(self.resume_file_path(), resume_data).await?;
        Ok(())
    }

    pub async fn load(file_path: &Path) -> Option<Self> {
        let resume_path = file_path.with_extension("boringcache-upload-resume");
        if let Ok(resume_data) = tokio::fs::read_to_string(&resume_path).await {
            serde_json::from_str(&resume_data).ok()
        } else {
            None
        }
    }

    pub fn cleanup(&self) -> Result<()> {
        let resume_path = self.resume_file_path();
        if resume_path.exists() {
            std::fs::remove_file(resume_path)?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.uploaded_parts.iter().all(|&uploaded| uploaded)
    }

    pub fn next_incomplete_part(&self) -> Option<usize> {
        self.uploaded_parts.iter().position(|&uploaded| !uploaded)
    }

    pub fn mark_part_complete(&mut self, part_index: usize, etag: String) {
        if part_index < self.uploaded_parts.len() {
            self.uploaded_parts[part_index] = true;
            self.part_etags[part_index] = Some(etag);
        }
    }

    pub fn get_completed_parts(&self) -> Vec<crate::api::PartInfo> {
        self.part_etags
            .iter()
            .enumerate()
            .filter_map(|(i, etag)| {
                etag.as_ref().map(|etag| crate::api::PartInfo {
                    part_number: (i + 1) as u32,
                    etag: etag.clone(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::time::Instant;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, MAX_RETRIES);
        assert_eq!(config.max_backoff_secs, MAX_BACKOFF_SECS);
        assert!(!config.verbose);
    }

    #[test]
    fn test_retry_config_new() {
        let config = RetryConfig::new(true);
        assert_eq!(config.max_retries, MAX_RETRIES);
        assert_eq!(config.max_backoff_secs, MAX_BACKOFF_SECS);
        assert!(config.verbose);
    }

    #[tokio::test]
    async fn test_retry_success_immediate() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<i32, anyhow::Error>(42)
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    let current_count = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if current_count < 3 {
                        Err(anyhow::anyhow!("Temporary failure"))
                    } else {
                        Ok::<i32, anyhow::Error>(42)
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_max_retries_reached() {
        let config = RetryConfig::new(false);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        let start_time = Instant::now();
        let call_count_clone = call_count.clone();
        let result = config
            .retry_with_backoff("test operation", move || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err::<i32, anyhow::Error>(anyhow::anyhow!("Always fails"))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert!(start_time.elapsed() >= Duration::from_secs(1));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed after 3 attempts"));
    }

    #[test]
    fn test_resume_info_creation() {
        let path = PathBuf::from("/tmp/test");
        let resume_info = ResumeInfo::new(path.clone(), 1000, 5);

        assert_eq!(resume_info.file_path, path);
        assert_eq!(resume_info.total_size, 1000);
        assert_eq!(resume_info.downloaded_size, 0);
        assert_eq!(resume_info.chunks_completed.len(), 5);
        assert!(resume_info
            .chunks_completed
            .iter()
            .all(|&completed| !completed));
    }

    #[test]
    fn test_resume_info_progress() {
        let mut resume_info = ResumeInfo::new(PathBuf::from("/tmp/test"), 1000, 4);
        assert_eq!(resume_info.progress_percentage(), 0.0);
        assert!(!resume_info.is_complete());
        assert_eq!(resume_info.next_incomplete_chunk(), Some(0));

        resume_info.mark_chunk_complete(0, 250);
        assert_eq!(resume_info.downloaded_size, 250);
        assert_eq!(resume_info.progress_percentage(), 25.0);
        assert!(!resume_info.is_complete());
        assert_eq!(resume_info.next_incomplete_chunk(), Some(1));

        resume_info.mark_chunk_complete(1, 250);
        resume_info.mark_chunk_complete(2, 250);
        resume_info.mark_chunk_complete(3, 250);
        assert_eq!(resume_info.downloaded_size, 1000);
        assert_eq!(resume_info.progress_percentage(), 100.0);
        assert!(resume_info.is_complete());
        assert_eq!(resume_info.next_incomplete_chunk(), None);
    }

    #[test]
    fn test_upload_resume_info_creation() {
        let path = PathBuf::from("/tmp/upload");
        let upload_info = UploadResumeInfo::new(path.clone(), "upload-123".to_string(), 2000, 3);

        assert_eq!(upload_info.file_path, path);
        assert_eq!(upload_info.upload_id, "upload-123");
        assert_eq!(upload_info.total_size, 2000);
        assert_eq!(upload_info.uploaded_parts.len(), 3);
        assert_eq!(upload_info.part_etags.len(), 3);
        assert!(upload_info.uploaded_parts.iter().all(|&uploaded| !uploaded));
        assert!(upload_info.part_etags.iter().all(|etag| etag.is_none()));
    }

    #[test]
    fn test_upload_resume_info_completion() {
        let mut upload_info = UploadResumeInfo::new(
            PathBuf::from("/tmp/upload"),
            "upload-123".to_string(),
            1500,
            3,
        );

        assert!(!upload_info.is_complete());
        assert_eq!(upload_info.next_incomplete_part(), Some(0));

        upload_info.mark_part_complete(0, "etag-1".to_string());
        assert!(!upload_info.is_complete());
        assert_eq!(upload_info.next_incomplete_part(), Some(1));

        upload_info.mark_part_complete(1, "etag-2".to_string());
        upload_info.mark_part_complete(2, "etag-3".to_string());
        assert!(upload_info.is_complete());
        assert_eq!(upload_info.next_incomplete_part(), None);

        let parts = upload_info.get_completed_parts();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].etag, "etag-1");
        assert_eq!(parts[1].part_number, 2);
        assert_eq!(parts[1].etag, "etag-2");
        assert_eq!(parts[2].part_number, 3);
        assert_eq!(parts[2].etag, "etag-3");
    }

    #[test]
    fn test_resume_info_edge_cases() {
        let resume_info = ResumeInfo::new(PathBuf::from("/tmp/empty"), 0, 1);
        assert_eq!(resume_info.progress_percentage(), 100.0);

        let mut resume_info = ResumeInfo::new(PathBuf::from("/tmp/test"), 1000, 2);
        let original_size = resume_info.downloaded_size;
        resume_info.mark_chunk_complete(5, 100);
        assert_eq!(resume_info.downloaded_size, original_size);
    }
}

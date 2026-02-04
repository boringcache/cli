use crate::progress::{Reporter, Summary};
use crate::types::{ByteSize, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct TransferProgress {
    reporter: Reporter,
    session_id: String,
    step_number: u8,
    total_bytes: u64,
    start_time: Instant,
    transferred_bytes: Arc<AtomicU64>,
}

impl TransferProgress {
    pub fn new(reporter: Reporter, session_id: String, step_number: u8, total_bytes: u64) -> Self {
        Self {
            reporter,
            session_id,
            step_number,
            total_bytes,
            start_time: Instant::now(),
            transferred_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn new_noop() -> Self {
        Self {
            reporter: Reporter::new_noop(),
            session_id: String::new(),
            step_number: 0,
            total_bytes: 0,
            start_time: Instant::now(),
            transferred_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_bytes(&self, bytes: u64) -> Result<()> {
        let total_transferred = self.transferred_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let progress_percent = if self.total_bytes > 0 {
            (total_transferred as f64 / self.total_bytes as f64 * 100.0).min(100.0)
        } else {
            100.0
        };

        let elapsed = self.start_time.elapsed();
        let bytes_per_second = if elapsed.as_secs_f64() > 0.0 {
            total_transferred as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let speed_str = ProgressFormat::format_speed(bytes_per_second);
        let remaining_bytes = self.total_bytes.saturating_sub(total_transferred);
        let eta_str = if remaining_bytes == 0 {
            "0s".to_string()
        } else {
            let eta = ProgressFormat::format_eta(remaining_bytes, bytes_per_second);
            if eta == "unknown" {
                "--".to_string()
            } else {
                eta
            }
        };

        let detail = format!(
            "{} / {} {} @ {} (ETA {})",
            ByteSize::new(total_transferred),
            ByteSize::new(self.total_bytes),
            ProgressFormat::format_percent(progress_percent),
            speed_str,
            eta_str
        );

        self.reporter.step_progress(
            self.session_id.clone(),
            self.step_number,
            progress_percent,
            Some(detail),
        )?;

        Ok(())
    }

    pub fn complete(&self) -> Result<()> {
        self.transferred_bytes
            .store(self.total_bytes, Ordering::Relaxed);
        self.record_bytes(0)?;
        Ok(())
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn transferred_bytes(&self) -> u64 {
        self.transferred_bytes.load(Ordering::Relaxed)
    }
}

pub struct ProgressSession {
    reporter: Reporter,
    session_id: String,
    start_time: Instant,
    current_step: u8,
}

impl ProgressSession {
    pub fn new(
        reporter: Reporter,
        session_id: String,
        title: String,
        total_steps: u8,
    ) -> Result<Self> {
        reporter.session_start(session_id.clone(), title, total_steps)?;

        Ok(Self {
            reporter,
            session_id,
            start_time: Instant::now(),
            current_step: 0,
        })
    }

    pub fn start_step(&mut self, title: String, detail: Option<String>) -> Result<StepHandle> {
        self.current_step += 1;
        let step_start = Instant::now();

        self.reporter
            .step_start(self.session_id.clone(), self.current_step, title, detail)?;

        Ok(StepHandle {
            reporter: self.reporter.clone(),
            session_id: self.session_id.clone(),
            step_number: self.current_step,
            start_time: step_start,
        })
    }

    pub fn complete(self, summary: Summary) -> Result<()> {
        self.reporter
            .session_complete(self.session_id, self.start_time.elapsed(), summary)?;
        Ok(())
    }

    pub fn error(self, error_message: String) -> Result<()> {
        self.reporter
            .session_error(self.session_id, error_message)?;
        Ok(())
    }
}

pub struct StepHandle {
    reporter: Reporter,
    session_id: String,
    step_number: u8,
    start_time: Instant,
}

impl StepHandle {
    pub fn step_number(&self) -> u8 {
        self.step_number
    }

    pub fn update_progress(&self, percent: f64, detail: Option<String>) -> Result<()> {
        self.reporter
            .step_progress(self.session_id.clone(), self.step_number, percent, detail)?;
        Ok(())
    }

    pub fn complete(self) -> Result<()> {
        self.reporter.step_complete(
            self.session_id,
            self.step_number,
            self.start_time.elapsed(),
        )?;
        Ok(())
    }
}

pub struct ProgressFormat;

impl ProgressFormat {
    pub fn format_speed(bytes_per_second: f64) -> String {
        if bytes_per_second < 1024.0 {
            format!("{:.1} B/s", bytes_per_second)
        } else if bytes_per_second < 1024.0 * 1024.0 {
            format!("{:.1} KB/s", bytes_per_second / 1024.0)
        } else if bytes_per_second < 1024.0 * 1024.0 * 1024.0 {
            format!("{:.1} MB/s", bytes_per_second / (1024.0 * 1024.0))
        } else {
            format!("{:.1} GB/s", bytes_per_second / (1024.0 * 1024.0 * 1024.0))
        }
    }

    pub fn format_eta(bytes_remaining: u64, bytes_per_second: f64) -> String {
        if bytes_per_second <= 0.0 {
            return "unknown".to_string();
        }

        let seconds_remaining = bytes_remaining as f64 / bytes_per_second;

        if seconds_remaining < 60.0 {
            format!("{}s", seconds_remaining as u32)
        } else if seconds_remaining < 3600.0 {
            let minutes = seconds_remaining as u32 / 60;
            let seconds = seconds_remaining as u32 % 60;
            format!("{}m{}s", minutes, seconds)
        } else {
            let hours = seconds_remaining as u32 / 3600;
            let minutes = (seconds_remaining as u32 % 3600) / 60;
            format!("{}h{}m", hours, minutes)
        }
    }

    pub fn format_percent(value: f64) -> String {
        format!("{:>3.0}%", value.clamp(0.0, 100.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_format_speed() {
        assert_eq!(ProgressFormat::format_speed(512.0), "512.0 B/s");
        assert_eq!(ProgressFormat::format_speed(1536.0), "1.5 KB/s");
        assert_eq!(ProgressFormat::format_speed(1572864.0), "1.5 MB/s");
    }

    #[test]
    fn test_progress_format_eta() {
        assert_eq!(ProgressFormat::format_eta(1000, 100.0), "10s");
        assert_eq!(ProgressFormat::format_eta(6000, 100.0), "1m0s");
        assert_eq!(ProgressFormat::format_eta(360000, 100.0), "1h0m");
    }

    #[test]
    fn test_progress_format_percent() {
        assert_eq!(ProgressFormat::format_percent(50.0), " 50%");
        assert_eq!(ProgressFormat::format_percent(100.0), "100%");
        assert_eq!(ProgressFormat::format_percent(150.0), "100%");
    }
}

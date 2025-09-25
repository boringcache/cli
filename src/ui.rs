use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

pub fn format_size(bytes: f64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;

    let mut size = bytes;
    let mut unit_index = 0;

    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

pub struct CleanUI;

pub struct SpinnerHandle {
    running: Arc<AtomicBool>,
}

impl SpinnerHandle {
    fn new() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut frame_idx = 0;

            tokio::time::sleep(Duration::from_millis(200)).await;

            while running_clone.load(Ordering::Relaxed) {
                print!("{}", frames[frame_idx]);
                let _ = io::stdout().flush();
                tokio::time::sleep(Duration::from_millis(80)).await;
                print!("\x08"); // Backspace to overwrite spinner char
                let _ = io::stdout().flush();
                frame_idx = (frame_idx + 1) % frames.len();
            }
        });

        Self { running }
    }

    pub fn stop(self) {
        self.running.store(false, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl CleanUI {
    pub fn start_operation(name: &str, count: usize) {
        println!("[+] {} ({}/{})", name, 0, count);
    }

    pub fn step_start(name: &str, detail: Option<&str>) {
        let detail_str = detail.map_or(String::new(), |d| format!(" {d}"));
        print!(" => {name}{detail_str}... ");
        let _ = io::stdout().flush();
    }

    pub fn step_start_with_spinner(name: &str, detail: Option<&str>) -> SpinnerHandle {
        let detail_str = detail.map_or(String::new(), |d| format!(" {d}"));
        print!(" => {name}{detail_str}... ");
        let _ = io::stdout().flush();

        SpinnerHandle::new()
    }

    pub fn step_success(duration_ms: Option<u64>) {
        let timing = duration_ms.map_or(String::new(), |ms| {
            if ms > 1000 {
                format!(" ({:.1}s)", ms as f64 / 1000.0)
            } else {
                format!(" ({ms}ms)")
            }
        });
        println!("OK{timing}");
    }

    pub fn step_start_with_progress(name: &str, detail: Option<&str>) {
        let detail_str = detail.map_or(String::new(), |d| format!(" {d}"));
        println!(" => {name}{detail_str}...");
    }

    pub fn step_error(error: &str) {
        println!(": FAILED - {error}");
    }

    pub fn complete_operation(name: &str, count: usize, total_duration_ms: u64) {
        let duration_str = if total_duration_ms > 1000 {
            format!("{:.1}s", total_duration_ms as f64 / 1000.0)
        } else {
            format!("{total_duration_ms}ms")
        };
        println!("[+] {name} complete: {count} items in {duration_str}");
    }

    pub fn cache_tier(tier: u8, description: &str) {
        println!(" => Tier {tier}: {description}");
    }

    pub fn info(message: &str) {
        println!(" => {message}");
    }

    pub fn error(message: &str) {
        eprintln!(" FAILED: {message}");
    }

    pub fn warning(message: &str) {
        eprintln!(" WARNING: {message}");
    }

    pub fn batch_start(operation: &str, count: usize, workspace: &str) {
        println!(
            "=> {} {} cache entries in workspace '{}'...",
            operation
                .chars()
                .next()
                .map(|c| c.to_uppercase().collect::<String>() + &operation[1..].to_lowercase())
                .unwrap_or_else(|| operation.to_string()),
            count,
            workspace
        );
        println!();
    }

    pub fn item_status(tag: &str, size_mb: f64) {
        println!("{tag}: {size_mb:.1} MB");
    }

    pub fn item_not_found(tag: &str) {
        println!("{tag}: not found");
    }

    pub fn item_exists_with_timing(tag: &str, duration_ms: u64) {
        let timing = if duration_ms > 1000 {
            format!(" ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" ({duration_ms}ms)")
        };
        println!("{tag}: already exists{timing}");
    }

    pub fn item_exists(tag: &str) {
        println!("{tag}: already exists");
    }

    pub fn item_start(tag: &str) {
        println!("=> {tag}");
    }

    pub fn item_archiving(file_count: usize, size_bytes: f64) {
        println!(
            "=> Archiving {} files ({})...",
            file_count,
            format_size(size_bytes)
        );
    }

    pub fn item_compressing(algorithm: &str) {
        print!("=> Compressing with {algorithm}...");
        let _ = io::stdout().flush();
    }

    pub fn item_compression_complete(duration_ms: u64) {
        let timing = if duration_ms > 1000 {
            format!(" OK ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" OK ({duration_ms}ms)")
        };
        println!("{timing}");
    }

    pub fn item_uploading_start(size_bytes: f64) -> SpinnerHandle {
        print!("=> Uploading {}...", format_size(size_bytes));
        let _ = io::stdout().flush();
        SpinnerHandle::new()
    }

    pub fn item_uploading_complete(spinner: SpinnerHandle, duration_ms: u64) {
        spinner.stop();
        let timing = if duration_ms > 1000 {
            format!(" OK ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" OK ({duration_ms}ms)")
        };
        println!("{timing}");
    }

    pub fn item_downloading_start(size_bytes: f64) -> SpinnerHandle {
        print!("=> Download {}...", format_size(size_bytes));
        let _ = io::stdout().flush();
        SpinnerHandle::new()
    }

    pub fn item_downloading_complete(spinner: SpinnerHandle, duration_ms: u64) {
        spinner.stop();
        let timing = if duration_ms > 1000 {
            format!(" OK ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" OK ({duration_ms}ms)")
        };
        println!("{timing}");
    }

    pub fn item_extracting_start() -> SpinnerHandle {
        print!("=> Extract...");
        let _ = io::stdout().flush();
        SpinnerHandle::new()
    }

    pub fn item_extracting_complete(spinner: SpinnerHandle, duration_ms: u64) {
        spinner.stop();
        let timing = if duration_ms > 1000 {
            format!(" OK ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" OK ({duration_ms}ms)")
        };
        println!("{timing}");
    }

    pub fn item_processing(tag: &str, action: &str, details: Option<&str>) {
        match details {
            Some(detail) => println!("{tag}: {action} {detail}"),
            None => println!("{tag}: {action}"),
        }
    }

    pub fn item_complete_with_timing(tag: &str, duration_ms: u64) {
        let timing = if duration_ms > 1000 {
            format!(" ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" ({duration_ms}ms)")
        };
        println!("{tag}: complete{timing}");
    }

    pub fn item_complete(tag: &str) {
        println!("{tag}: complete");
    }

    pub fn item_error(tag: &str, error: &str) {
        println!("{tag}: {error}");
    }

    pub fn section_break() {
        println!();
    }

    pub fn batch_summary(operation: &str, successful: usize, total: usize, workspace: &str) {
        println!();
        if successful == total {
            println!(
                "=> Successfully {} {} entries in workspace '{}'",
                operation.to_lowercase(),
                successful,
                workspace
            );
        } else {
            println!(
                "=> {} {} of {} entries in workspace '{}'",
                operation
                    .chars()
                    .next()
                    .unwrap()
                    .to_uppercase()
                    .collect::<String>()
                    + &operation[1..].to_lowercase(),
                successful,
                total,
                workspace
            );
        }
    }

    pub fn batch_summary_restore(items: &str, _workspace: &str) {
        println!();
        println!("=> Successfully restored {items}");
    }

    pub fn item_progress_simple(tag: &str, action: &str) {
        println!("{tag}: {action}");
    }

    pub fn item_complete_with_spacing_and_timing(tag: &str, duration_ms: u64) {
        let timing = if duration_ms > 1000 {
            format!(" ({:.1}s)", duration_ms as f64 / 1000.0)
        } else {
            format!(" ({duration_ms}ms)")
        };
        println!("{tag}: complete{timing}");
        println!(); // Add spacing after completion
    }

    pub fn item_complete_with_spacing(tag: &str) {
        println!("{tag}: complete");
        println!(); // Add spacing after completion
    }
}

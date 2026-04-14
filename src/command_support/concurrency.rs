use crate::ui;

const SAVE_MAX_CONCURRENCY_ENV: &str = "BORINGCACHE_SAVE_MAX_CONCURRENCY";
const RESTORE_MAX_CONCURRENCY_ENV: &str = "BORINGCACHE_RESTORE_MAX_CONCURRENCY";

pub fn get_optimal_concurrency(operation_count: usize, operation_type: &str) -> usize {
    let resources = crate::platform::resources::SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();

    let base_concurrency = match operation_type {
        "save" => {
            let cpu_count = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            std::cmp::max(4, cpu_count)
        }
        "restore" => resources.recommended_download_concurrency(is_ci),
        _ => 4,
    };

    let platform_adjusted = match operation_type {
        "restore" => base_concurrency,
        _ if cfg!(target_os = "macos") => base_concurrency + 2,
        _ if cfg!(target_os = "windows") => std::cmp::max(2, base_concurrency - 1),
        _ => base_concurrency,
    };

    let hard_cap = match operation_type {
        "save" => 16,
        "restore" => 24,
        _ => 16,
    };

    let env_cap = match operation_type {
        "save" => parse_concurrency_env(SAVE_MAX_CONCURRENCY_ENV),
        "restore" => parse_concurrency_env(RESTORE_MAX_CONCURRENCY_ENV),
        _ => None,
    };
    let effective_cap = env_cap.unwrap_or(hard_cap).clamp(1, 128);

    std::cmp::min(
        std::cmp::min(platform_adjusted, effective_cap),
        operation_count,
    )
}

pub fn display_concurrency_info(max_concurrent: usize, operation_type: &str) {
    ui::info(&format!(
        "Using {max_concurrent} concurrent {operation_type} operations"
    ));
}

fn parse_concurrency_env(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok().filter(|value| *value > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn get_optimal_concurrency_respects_operation_count() {
        assert_eq!(get_optimal_concurrency(1, "save"), 1);
        assert!(get_optimal_concurrency(8, "restore") >= 2);
    }

    #[test]
    fn get_optimal_concurrency_honors_save_env_cap() {
        let _guard = env_lock().lock().unwrap();
        test_env::set_var(SAVE_MAX_CONCURRENCY_ENV, "2");
        assert_eq!(get_optimal_concurrency(8, "save"), 2);
        test_env::remove_var(SAVE_MAX_CONCURRENCY_ENV);
    }

    #[test]
    fn get_optimal_concurrency_honors_restore_env_cap() {
        let _guard = env_lock().lock().unwrap();
        test_env::set_var(RESTORE_MAX_CONCURRENCY_ENV, "3");
        assert_eq!(get_optimal_concurrency(8, "restore"), 3);
        test_env::remove_var(RESTORE_MAX_CONCURRENCY_ENV);
    }

    #[test]
    fn get_optimal_concurrency_ignores_invalid_env_cap() {
        let _guard = env_lock().lock().unwrap();
        test_env::set_var(SAVE_MAX_CONCURRENCY_ENV, "0");
        let without_override = get_optimal_concurrency(8, "save");
        assert!(without_override >= 1);
        test_env::remove_var(SAVE_MAX_CONCURRENCY_ENV);
    }
}

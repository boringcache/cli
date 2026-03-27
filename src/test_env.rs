use std::env;
use std::ffi::OsStr;
use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub struct Guard {
    _guard: MutexGuard<'static, ()>,
}

pub fn lock() -> Guard {
    Guard {
        _guard: ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    }
}

pub fn set_var<K, V>(key: K, value: V)
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    // SAFETY: tests hold the process-wide guard from `lock()` before mutating
    // process environment variables.
    unsafe { env::set_var(key, value) };
}

pub fn remove_var<K>(key: K)
where
    K: AsRef<OsStr>,
{
    // SAFETY: tests hold the process-wide guard from `lock()` before mutating
    // process environment variables.
    unsafe { env::remove_var(key) };
}

mod config;
mod policy;

#[cfg(test)]
mod tests;

pub const MAX_RETRIES: u32 = 3;
pub const MAX_BACKOFF_SECS: u64 = 8;

pub use config::RetryConfig;

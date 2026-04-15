mod classify;
mod convert;
mod kinds;

#[cfg(test)]
mod tests;

pub use classify::{is_connection_error, is_non_retryable_error};
pub use kinds::{BoringCacheError, ConflictMetadata, PendingMetadata};

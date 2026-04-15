pub mod common;
mod model;
mod render;
mod reporter;
mod system;

#[cfg(test)]
mod tests;

pub use common::{ProgressFormat, ProgressSession, StepHandle, TransferProgress};
pub use model::{Event, Summary};
pub use reporter::Reporter;
pub use system::System;

use humansize::{DECIMAL, format_size};

pub fn format_bytes(bytes: u64) -> String {
    format_size(bytes, DECIMAL)
}

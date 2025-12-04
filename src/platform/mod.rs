pub mod container;
/// Platform detection and system resource management
///
/// This module provides platform detection capabilities and system resource
/// assessment for optimal cache operations.
pub mod detection;
pub mod resources;

pub use container::ContainerDetection;
pub use detection::{Platform, PlatformInfo};
pub use resources::{DiskType, MemoryStrategy, SystemResources};

use crate::types::Result;

/// Unified platform and resource detection
pub fn detect_environment() -> Result<(Platform, SystemResources)> {
    let platform = Platform::detect()?;
    let resources = SystemResources::detect().clone();
    Ok((platform, resources))
}

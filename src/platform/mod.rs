pub mod container;

pub mod detection;
pub mod resources;

pub use container::ContainerDetection;
pub use detection::{Platform, PlatformInfo};
pub use resources::{DiskType, MemoryStrategy, SystemResources};

use crate::types::Result;

pub fn detect_environment() -> Result<(Platform, SystemResources)> {
    let platform = Platform::detect()?;
    let resources = SystemResources::detect().clone();
    Ok((platform, resources))
}

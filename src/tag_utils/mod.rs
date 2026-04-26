mod platform;
mod resolver;
mod validation;

#[cfg(test)]
mod tests;

pub use platform::{apply_platform_to_tag, apply_platform_to_tag_with_instance};
pub use resolver::TagResolver;
pub use validation::{server_cache_tag_name, validate_tag};

mod context;
mod detect;

#[cfg(test)]
mod tests;

pub use context::CiContext;
pub use detect::{build_tags_string, detect_ci_context, detect_ci_environment};

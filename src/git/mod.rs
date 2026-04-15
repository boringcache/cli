mod context;
mod detect;
mod normalize;

#[cfg(test)]
mod tests;

pub use context::GitContext;
pub use detect::is_git_disabled_by_env;

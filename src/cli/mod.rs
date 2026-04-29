mod adapters;
mod app;
mod auth;
mod cache;
mod config;
mod proxy;
mod workspace;

#[doc(hidden)]
pub mod dispatch;
#[doc(hidden)]
pub mod preprocess;

#[cfg(test)]
mod tests;

pub use adapters::AdapterArgs;
pub use app::{Cli, Commands};
pub use auth::{AuthArgs, LoginArgs, TokenCommands};
pub use cache::{
    AnalyzeArgs, CheckArgs, DeleteArgs, InspectArgs, LsArgs, MissesArgs, MountArgs, RestoreArgs,
    RunArgs, SaveArgs, SessionsArgs, StatusArgs, TagsArgs,
};
pub use config::{ConfigArgs, ConfigSubcommand, SetupEncryptionArgs};
pub use proxy::{CacheRegistryArgs, GoCacheProgArgs};
pub use workspace::{AuditArgs, DashboardArgs, DoctorArgs, OnboardArgs, UseArgs, WorkspacesArgs};

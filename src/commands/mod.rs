#[path = "adapters/mod.rs"]
mod adapters_group;
#[path = "auth/mod.rs"]
mod auth_group;
#[path = "cache/mod.rs"]
mod cache_group;
#[path = "config/mod.rs"]
mod config_group;
#[path = "proxy/mod.rs"]
mod proxy_group;
#[path = "workspace/mod.rs"]
mod workspace_group;

pub use adapters_group::{command as adapter, go_cacheprog};
pub use auth_group::{auth, login, token};
pub use cache_group::{
    check, delete, inspect, ls, misses, mount, restore, run, save, sessions, status, tags,
};
pub use config_group::{config, setup_encryption};
pub use proxy_group::cache_registry;
pub use workspace_group::{audit, dashboard, doctor, onboard, use_workspace, workspaces};

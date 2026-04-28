use super::*;

#[path = "tool_routes/bazel.rs"]
mod bazel;
#[path = "tool_routes/go_cache.rs"]
mod go_cache;
#[path = "tool_routes/gradle.rs"]
mod gradle;
#[path = "tool_routes/maven.rs"]
mod maven;
#[path = "tool_routes/nx.rs"]
mod nx;
#[path = "tool_routes/sccache.rs"]
mod sccache;
#[path = "tool_routes/turborepo.rs"]
mod turborepo;

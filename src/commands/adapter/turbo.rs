use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::commands::proxy_exec;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "turbo",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(set: &mut BTreeMap<String, String>, context: &proxy_exec::ProxyContext) {
    set.insert("TURBO_API".to_string(), context.endpoint());
    set.insert(
        "TURBO_TOKEN".to_string(),
        proxy_exec::PROXY_AUTH_TOKEN.to_string(),
    );
    set.insert(
        "TURBO_TEAM".to_string(),
        proxy_exec::PROXY_AUTH_TOKEN.to_string(),
    );
}

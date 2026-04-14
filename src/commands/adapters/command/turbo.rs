use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "turbo",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(set: &mut BTreeMap<String, String>, context: &proxy::ProxyContext) {
    set.insert("TURBO_API".to_string(), context.endpoint());
    set.insert(
        "TURBO_TOKEN".to_string(),
        proxy::PROXY_AUTH_TOKEN.to_string(),
    );
    set.insert(
        "TURBO_TEAM".to_string(),
        proxy::PROXY_AUTH_TOKEN.to_string(),
    );
}

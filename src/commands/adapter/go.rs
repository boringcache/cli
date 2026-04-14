use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::commands::proxy_exec;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "go",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(set: &mut BTreeMap<String, String>, context: &proxy_exec::ProxyContext) {
    set.insert(
        "GOCACHEPROG".to_string(),
        format!("boringcache go-cacheprog --endpoint {}", context.endpoint()),
    );
}

use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "go",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(set: &mut BTreeMap<String, String>, context: &proxy::ProxyContext) {
    set.insert(
        "GOCACHEPROG".to_string(),
        format!("boringcache go-cacheprog --endpoint {}", context.endpoint()),
    );
}

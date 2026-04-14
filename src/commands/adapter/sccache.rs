use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::commands::proxy_exec;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "sccache",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(set: &mut BTreeMap<String, String>, context: &proxy_exec::ProxyContext) {
    let endpoint = context.endpoint();
    set.insert("RUSTC_WRAPPER".to_string(), "sccache".to_string());
    set.insert(
        "SCCACHE_WEBDAV_ENDPOINT".to_string(),
        format!("{endpoint}/"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::adapter::AdapterKind;

    #[test]
    fn sccache_env_plan_sets_webdav_backend() {
        let context = proxy_exec::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(&context);
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_ENDPOINT"),
            Some(&"http://127.0.0.1:5000/".to_string())
        );
        assert_eq!(plan.set.get("RUSTC_WRAPPER"), Some(&"sccache".to_string()));
    }
}

use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "sccache",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(
    set: &mut BTreeMap<String, String>,
    context: &proxy::ProxyContext,
    options: &super::AdapterCommandOptions,
) {
    let endpoint = context.endpoint();
    set.insert("RUSTC_WRAPPER".to_string(), "sccache".to_string());
    set.insert(
        "SCCACHE_WEBDAV_ENDPOINT".to_string(),
        format!("{endpoint}/"),
    );
    set.insert(
        "SCCACHE_WEBDAV_KEY_PREFIX".to_string(),
        options.sccache_key_prefix.clone().unwrap_or_default(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::adapter::AdapterKind;

    #[test]
    fn sccache_env_plan_sets_webdav_backend() {
        let context = proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(
            &context,
            &super::super::AdapterCommandOptions {
                cache_ref_tag: "buildcache".to_string(),
                cache_mode: "max".to_string(),
                read_only: false,
                sccache_key_prefix: None,
            },
        );
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_ENDPOINT"),
            Some(&"http://127.0.0.1:5000/".to_string())
        );
        assert_eq!(plan.set.get("RUSTC_WRAPPER"), Some(&"sccache".to_string()));
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_KEY_PREFIX"),
            Some(&String::new())
        );
    }

    #[test]
    fn sccache_env_plan_sets_configured_key_prefix() {
        let context = proxy::ProxyContext {
            endpoint_host: "127.0.0.1".to_string(),
            port: 5000,
            cache_ref: "127.0.0.1:5000/cache:test".to_string(),
        };

        let plan = AdapterKind::Sccache.proxy_env_plan(
            &context,
            &super::super::AdapterCommandOptions {
                cache_ref_tag: "buildcache".to_string(),
                cache_mode: "max".to_string(),
                read_only: false,
                sccache_key_prefix: Some("rust/ci".to_string()),
            },
        );
        assert_eq!(
            plan.set.get("SCCACHE_WEBDAV_KEY_PREFIX"),
            Some(&"rust/ci".to_string())
        );
    }
}

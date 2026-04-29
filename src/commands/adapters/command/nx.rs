use std::collections::BTreeMap;
use std::fs;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;
use crate::ui;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "nx",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(
    set: &mut BTreeMap<String, String>,
    context: &proxy::ProxyContext,
    _: &super::AdapterCommandOptions,
) {
    warn_if_nx_cloud_workspace_binding_detected();
    set.insert(
        "NX_SELF_HOSTED_REMOTE_CACHE_SERVER".to_string(),
        context.endpoint(),
    );
    set.insert(
        "NX_SELF_HOSTED_REMOTE_CACHE_ACCESS_TOKEN".to_string(),
        proxy::PROXY_AUTH_TOKEN.to_string(),
    );
}

fn warn_if_nx_cloud_workspace_binding_detected() {
    let Ok(nx_json_path) = std::env::current_dir().map(|dir| dir.join("nx.json")) else {
        return;
    };
    let Ok(contents) = fs::read_to_string(nx_json_path) else {
        return;
    };
    let Ok(nx_json) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return;
    };

    if !uses_nx_cloud(&nx_json) {
        return;
    }

    ui::warn(
        "Nx Cloud workspace binding detected in nx.json. BoringCache will set Nx's self-hosted remote-cache endpoint, but Nx may still select its Nx Cloud runner first. For BoringCache Nx proxy runs, remove the Nx Cloud binding from the workspace config or use a disposable prepared checkout.",
    );
}

fn uses_nx_cloud(nx_json: &serde_json::Value) -> bool {
    nx_json.get("nxCloudId").is_some()
        || nx_json.get("nxCloudAccessToken").is_some()
        || nx_json
            .get("tasksRunnerOptions")
            .and_then(serde_json::Value::as_object)
            .map(|runners| {
                runners.values().any(|runner| {
                    runner
                        .get("runner")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| name == "nx-cloud" || name == "@nrwl/nx-cloud")
                })
            })
            .unwrap_or(false)
}

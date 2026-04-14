use super::{AdapterRunner, no_extra_proxy_env, passthrough_command};

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "maven",
    inject_proxy_env: no_extra_proxy_env,
    prepare_command: passthrough_command,
};

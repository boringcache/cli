pub mod command;

pub(crate) use command::{
    ChildOutcome, PROXY_AUTH_TOKEN, ProxyContext, spawn_command, status_exit_code,
    substitute_proxy_placeholders,
};

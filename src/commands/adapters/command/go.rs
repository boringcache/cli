use std::collections::BTreeMap;

use super::{AdapterRunner, passthrough_command};
use crate::proxy;

pub(super) const RUNNER: AdapterRunner = AdapterRunner {
    name: "go",
    inject_proxy_env,
    prepare_command: passthrough_command,
};

fn inject_proxy_env(
    set: &mut BTreeMap<String, String>,
    context: &proxy::ProxyContext,
    _: &super::AdapterCommandOptions,
) {
    set.insert(
        "GOCACHEPROG".to_string(),
        go_cacheprog_command(&context.endpoint()),
    );
}

fn go_cacheprog_command(endpoint: &str) -> String {
    let executable = std::env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "boringcache".to_string());

    format!(
        "{} go-cacheprog --endpoint {}",
        shell_quote(&executable),
        shell_quote(endpoint)
    )
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.' | ':' | '='))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_cacheprog_command_uses_current_executable() {
        let current = std::env::current_exe()
            .expect("current executable")
            .into_os_string()
            .into_string()
            .expect("utf-8 test executable");

        let command = go_cacheprog_command("http://127.0.0.1:15476");

        assert!(command.starts_with(&shell_quote(&current)));
        assert!(command.contains(" go-cacheprog --endpoint http://127.0.0.1:15476"));
        assert!(!command.starts_with("boringcache go-cacheprog"));
    }

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("/tmp/boringcache"), "/tmp/boringcache");
        assert_eq!(
            shell_quote("/tmp/boring cache/it's"),
            "'/tmp/boring cache/it'\\''s'"
        );
    }
}

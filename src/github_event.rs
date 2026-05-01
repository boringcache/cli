pub(crate) fn json_from_env() -> Option<serde_json::Value> {
    let path = crate::config::env_var("GITHUB_EVENT_PATH")?;
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes).ok()
}

pub(crate) fn default_branch_from_env() -> Option<String> {
    json_from_env()?
        .get("repository")
        .and_then(|repository| repository.get("default_branch"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

pub(crate) fn pull_request_number_from_env() -> Option<u32> {
    let json = json_from_env()?;
    json.get("number")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .or_else(|| {
            json.get("pull_request")
                .and_then(|pull_request| pull_request.get("number"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
        })
}

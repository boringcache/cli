use anyhow::Result;
use serde::Serialize;

pub(crate) const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct VersionedJson<'a, T: Serialize> {
    schema_version: u32,
    #[serde(flatten)]
    payload: &'a T,
}

pub(crate) fn print<T: Serialize>(payload: &T) -> Result<()> {
    println!("{}", to_pretty_string(payload)?);
    Ok(())
}

pub(crate) fn to_pretty_string<T: Serialize>(payload: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(&VersionedJson {
        schema_version: SCHEMA_VERSION,
        payload,
    })?)
}

#[cfg(test)]
pub(crate) fn to_value<T: Serialize>(payload: &T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(VersionedJson {
        schema_version: SCHEMA_VERSION,
        payload,
    })?)
}

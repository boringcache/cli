use anyhow::Result;
use serde_json::json;

pub async fn execute(
    workspace_option: Option<String>,
    period: String,
    limit: u32,
    json_output: bool,
) -> Result<()> {
    let status = crate::commands::status::load_status(
        workspace_option,
        &period,
        limit,
        "boringcache misses <workspace>",
    )
    .await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "workspace": &status.workspace,
                "period": &status.period,
                "generated_at": &status.generated_at,
                "cache_health": &status.operations.cache_health,
                "missed_keys": &status.missed_keys,
            }))?
        );
        return Ok(());
    }

    crate::commands::status::render_misses_report(&status);
    Ok(())
}

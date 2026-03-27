use crate::commands::onboard::{
    ensure_default_workspace_after_onboarding, run_cli_connect_onboarding,
};
use crate::config::Config;
use crate::types::Result;
use crate::ui;
use std::io::IsTerminal;

pub async fn execute() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "'boringcache login' requires an interactive terminal. Use 'boringcache auth --token <token>' for non-interactive auth."
        );
    }

    let token = run_cli_connect_onboarding().await?;
    crate::commands::auth::execute(token.clone()).await?;
    ensure_default_workspace_after_onboarding(&token).await?;

    if let Ok(config) = Config::load()
        && let Some(ref ws) = config.default_workspace
    {
        ui::blank_line();
        ui::info("Ready. Try:");
        ui::info("  boringcache onboard");
        ui::info(&format!(
            "  boringcache run {} \"deps:node_modules\" -- npm ci",
            ws
        ));
    }

    Ok(())
}

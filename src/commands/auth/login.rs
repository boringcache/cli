use crate::commands::onboard::{
    CliEmailAuthOptions, ensure_default_workspace_after_onboarding, run_cli_connect_onboarding,
};
use crate::config::Config;
use crate::types::Result;
use crate::ui;
use std::io::IsTerminal;

pub async fn execute(
    manual: bool,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "'boringcache login' requires an interactive terminal. Use 'boringcache auth --token <token>' for non-interactive auth."
        );
    }

    let cli_email_auth = CliEmailAuthOptions::from_inputs(email, name, username);
    let token = run_cli_connect_onboarding(manual, cli_email_auth).await?;
    crate::commands::auth::execute_with_options(token.clone(), false).await?;
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

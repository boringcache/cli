use crate::api::ApiClient;
use crate::config::Config;
use crate::ui;
use anyhow::Result;

pub async fn execute(token: String) -> Result<()> {
    ui::info("Validating token with server...");

    let api_client = ApiClient::new_with_token_override(Some(token.clone()))?;
    let session_info = api_client.validate_token(&token).await?;

    Config::save(token)?;

    ui::info("Token validated successfully!");

    match session_info.token.scope_type.as_str() {
        "user" => ui::info(&format!("Scope: Personal ({})", session_info.user.name)),
        "organization" => {
            if let Some(org) = &session_info.organization {
                ui::info(&format!("Scope: Organization ({})", org.name));
            } else {
                ui::info("Scope: Organization");
            }
        }
        "workspace" => {
            if let Some(ws) = &session_info.workspace {
                ui::info(&format!("Scope: Workspace ({})", ws.name));
            } else {
                ui::info("Scope: Workspace");
            }
        }
        _ => ui::info(&format!(
            "Scope: {} ({})",
            session_info.token.scope_type, session_info.user.name
        )),
    }

    ui::info(&format!(
        "Token: {} ({})",
        session_info.token.name, session_info.token.id
    ));

    if let Some(expires_at) = session_info.token.expires_at {
        ui::info(&format!("Expires: {expires_at}"));
    } else if let Some(expires_in_days) = session_info.token.expires_in_days {
        if expires_in_days < 30 {
            ui::info(&format!(
                "Warning: Token expires in {expires_in_days} days - consider refreshing"
            ));
        } else {
            ui::info(&format!("Token expires in {expires_in_days} days"));
        }
    } else {
        ui::info("Token never expires");
    }

    if let Some(last_used) = session_info.token.last_used_at {
        ui::info(&format!("Last used: {last_used}"));
    }

    ui::info("Token saved to ~/.boringcache/config.json");
    Ok(())
}

use crate::api::{
    ApiClient,
    models::workspace::{
        WorkspaceApiToken, WorkspaceIssuedToken, WorkspaceTokenCreateParams,
        WorkspaceTokenCreateRequest, WorkspaceTokenPairCreateParams,
        WorkspaceTokenPairCreateRequest, WorkspaceTokenPairResponse, WorkspaceTokenResponse,
        WorkspaceTokenRotateParams, WorkspaceTokenRotateRequest, WorkspaceTokensResponse,
    },
};
use anyhow::{Result, anyhow};

pub async fn list(
    workspace_option: Option<String>,
    include_inactive: bool,
    limit: u32,
    page: u32,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_admin()?;
    let workspace = crate::commands::utils::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache token ls <workspace>",
    )
    .await?;
    let offset = (page.saturating_sub(1)).saturating_mul(limit);
    let response = api_client
        .workspace_tokens(&workspace, include_inactive, limit, offset)
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_token_list(&response);
    Ok(())
}

pub async fn create(
    workspace_option: Option<String>,
    name: String,
    access_level: String,
    write_tag_prefixes: Vec<String>,
    expires_in: Option<String>,
    expires_on: Option<String>,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_admin()?;
    let workspace = crate::commands::utils::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache token create <workspace> --name <name>",
    )
    .await?;
    let (expiration_preset, custom_expires_on) = resolve_expiration_args(expires_in, expires_on)?;

    let response = api_client
        .create_workspace_token(
            &workspace,
            &WorkspaceTokenCreateRequest {
                token: WorkspaceTokenCreateParams {
                    name,
                    access_level,
                    write_tag_prefixes,
                    expiration_preset,
                    custom_expires_on,
                },
            },
        )
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_issued_token("Token Created", &response);
    Ok(())
}

pub async fn create_ci(
    workspace_option: Option<String>,
    name_prefix: Option<String>,
    save_tag_prefixes: Vec<String>,
    expires_in: Option<String>,
    expires_on: Option<String>,
    json_output: bool,
) -> Result<()> {
    let api_client = ApiClient::for_admin()?;
    let workspace = crate::commands::utils::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache token create-ci <workspace>",
    )
    .await?;
    let (expiration_preset, custom_expires_on) = resolve_expiration_args(expires_in, expires_on)?;

    let response = api_client
        .create_workspace_token_pair(
            &workspace,
            &WorkspaceTokenPairCreateRequest {
                token_pair: WorkspaceTokenPairCreateParams {
                    name_prefix,
                    save_tag_prefixes,
                    expiration_preset,
                    custom_expires_on,
                },
            },
        )
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_token_pair("Token Pair Created", &response);
    Ok(())
}

pub async fn revoke(
    workspace_or_token_id: String,
    token_id: Option<String>,
    json_output: bool,
) -> Result<()> {
    let (workspace_option, token_id) =
        parse_token_target_args("revoke", workspace_or_token_id, token_id)?;
    let api_client = ApiClient::for_admin()?;
    let workspace = crate::commands::utils::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache token revoke <workspace> <token-id>",
    )
    .await?;

    let response = api_client
        .revoke_workspace_token(&workspace, &token_id)
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_token_state_change("Token Revoked", &response);
    Ok(())
}

pub async fn rotate(
    workspace_or_token_id: String,
    token_id: Option<String>,
    name: Option<String>,
    expires_in: Option<String>,
    expires_on: Option<String>,
    json_output: bool,
) -> Result<()> {
    let (workspace_option, token_id) =
        parse_token_target_args("rotate", workspace_or_token_id, token_id)?;
    let api_client = ApiClient::for_admin()?;
    let workspace = crate::commands::utils::resolve_workspace(
        &api_client,
        workspace_option,
        "boringcache token rotate <workspace> <token-id>",
    )
    .await?;
    let (expiration_preset, custom_expires_on) = resolve_expiration_args(expires_in, expires_on)?;

    let response = api_client
        .rotate_workspace_token(
            &workspace,
            &token_id,
            &WorkspaceTokenRotateRequest {
                token: WorkspaceTokenRotateParams {
                    name,
                    expiration_preset,
                    custom_expires_on,
                },
            },
        )
        .await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    render_rotated_token(&response);
    Ok(())
}

fn render_token_list(response: &WorkspaceTokensResponse) {
    crate::ui::blank_line();
    println!("Tokens");
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    crate::commands::status::print_field(
        "Scope",
        if response.filter.include_inactive {
            "all tokens"
        } else {
            "active tokens"
        },
    );
    crate::commands::status::print_field("Showing", &showing_range(&response.pagination));
    crate::ui::blank_line();

    if response.tokens.is_empty() {
        println!("  none");
        return;
    }

    println!(
        "  {:<16} {:<8} {:<8} {:<10} {:<10} NAME",
        "ID", "ACCESS", "STATE", "EXPIRES", "LAST USED"
    );
    println!("  {}", "-".repeat(86));

    for token in &response.tokens {
        println!(
            "  {:<16} {:<8} {:<8} {:<10} {:<10} {}",
            token.id,
            token.access_level,
            token.state,
            format_expiry(token),
            format_last_used(token),
            crate::commands::status::truncate(&token.name, 32),
        );

        if !token.write_tag_prefixes.is_empty() {
            println!(
                "    prefixes: {}",
                crate::commands::status::truncate(&token.write_tag_prefixes.join(", "), 96)
            );
        }
    }

    crate::ui::blank_line();
    println!("Create: boringcache token create --name <name>");
    println!("CI pair: boringcache token create-ci");

    if response.pagination.has_more {
        println!("Next page: {}", next_page_command(response));
    }
}

fn render_issued_token(title: &str, response: &WorkspaceTokenResponse) {
    crate::ui::blank_line();
    println!("{title}");
    print_token_summary(response);
    crate::ui::blank_line();

    if let Some(value) = response.value.as_deref() {
        println!("Value");
        println!("  {value}");
        crate::ui::blank_line();
        println!("Use");
        println!("  boringcache auth --token {}", shell_quote(value));
        println!(
            "  export {}={}",
            token_env_var(&response.token.access_level),
            shell_quote(value)
        );
    }
}

fn render_token_pair(title: &str, response: &WorkspaceTokenPairResponse) {
    crate::ui::blank_line();
    println!("{title}");
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    crate::ui::blank_line();

    println!("Restore");
    render_issued_token_block(&response.restore);
    crate::ui::blank_line();

    println!("Save");
    render_issued_token_block(&response.save);
    crate::ui::blank_line();

    println!("Export");
    println!(
        "  export BORINGCACHE_RESTORE_TOKEN={}",
        shell_quote(&response.restore.value)
    );
    println!(
        "  export BORINGCACHE_SAVE_TOKEN={}",
        shell_quote(&response.save.value)
    );
}

fn render_token_state_change(title: &str, response: &WorkspaceTokenResponse) {
    crate::ui::blank_line();
    println!("{title}");
    print_token_summary(response);
}

fn render_rotated_token(response: &WorkspaceTokenResponse) {
    crate::ui::blank_line();
    println!("Token Rotated");
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    if let Some(source) = response.rotated_from.as_ref() {
        crate::commands::status::print_field(
            "Replaced",
            &format!("{} ({})", source.name, source.id),
        );
    }
    crate::commands::status::print_field("Id", &response.token.id);
    crate::commands::status::print_field("Name", &response.token.name);
    crate::commands::status::print_field("Access", &response.token.access_level);
    crate::commands::status::print_field("Expires", &format_expiry(&response.token));
    if !response.token.write_tag_prefixes.is_empty() {
        crate::commands::status::print_field(
            "Prefixes",
            &response.token.write_tag_prefixes.join(", "),
        );
    }

    crate::ui::blank_line();
    if let Some(value) = response.value.as_deref() {
        println!("Value");
        println!("  {value}");
        crate::ui::blank_line();
        println!("Update");
        println!(
            "  export {}={}",
            token_env_var(&response.token.access_level),
            shell_quote(value)
        );
    }

    if let Some(source) = response.rotated_from.as_ref() {
        crate::ui::blank_line();
        println!("After updating secrets");
        println!(
            "  boringcache token revoke {} {}",
            response.workspace.slug, source.id
        );
    }
}

fn render_issued_token_block(token: &WorkspaceIssuedToken) {
    println!("  Id: {}", token.token.id);
    println!("  Name: {}", token.token.name);
    println!("  Access: {}", token.token.access_level);
    println!("  Expires: {}", format_expiry(&token.token));
    if !token.token.write_tag_prefixes.is_empty() {
        println!("  Prefixes: {}", token.token.write_tag_prefixes.join(", "));
    }
    println!("  Value: {}", token.value);
}

fn print_token_summary(response: &WorkspaceTokenResponse) {
    crate::commands::status::print_field("Workspace", &response.workspace.slug);
    crate::commands::status::print_field("Id", &response.token.id);
    crate::commands::status::print_field("Name", &response.token.name);
    crate::commands::status::print_field("Access", &response.token.access_level);
    crate::commands::status::print_field("State", &response.token.state);
    crate::commands::status::print_field("Expires", &format_expiry(&response.token));
    if !response.token.write_tag_prefixes.is_empty() {
        crate::commands::status::print_field(
            "Prefixes",
            &response.token.write_tag_prefixes.join(", "),
        );
    }
}

fn parse_token_target_args(
    action: &str,
    workspace_or_token_id: String,
    token_id: Option<String>,
) -> Result<(Option<String>, String)> {
    let first = workspace_or_token_id.trim().to_string();
    let second = token_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match second {
        Some(token_id) => Ok((Some(first), token_id)),
        None if first.contains('/') => Err(anyhow!(
            "Missing token id. Use `boringcache token {action} <workspace> <token-id>`."
        )),
        None => Ok((None, first)),
    }
}

fn resolve_expiration_args(
    expires_in: Option<String>,
    expires_on: Option<String>,
) -> Result<(Option<String>, Option<String>)> {
    if expires_in.is_some() && expires_on.is_some() {
        return Err(anyhow!(
            "Use either `--expires-in` or `--expires-on`, not both."
        ));
    }

    let expiration_preset = expires_in.map(|value| match value.as_str() {
        "30d" => "30_days".to_string(),
        "90d" => "90_days".to_string(),
        "1y" => "1_year".to_string(),
        other => other.to_string(),
    });

    Ok((expiration_preset, expires_on))
}

fn token_env_var(access_level: &str) -> &'static str {
    match access_level {
        "restore" => "BORINGCACHE_RESTORE_TOKEN",
        "save" => "BORINGCACHE_SAVE_TOKEN",
        _ => "BORINGCACHE_ADMIN_TOKEN",
    }
}

fn format_expiry(token: &WorkspaceApiToken) -> String {
    match token.state.as_str() {
        "revoked" => "revoked".to_string(),
        "expired" => "expired".to_string(),
        _ => match token.expires_in_days {
            Some(days) if days >= 0 => format!("{days}d"),
            _ => token
                .expires_at
                .as_deref()
                .map(crate::commands::status::format_relative_time)
                .unwrap_or_else(|| "never".to_string()),
        },
    }
}

fn format_last_used(token: &WorkspaceApiToken) -> String {
    token
        .last_used_at
        .as_deref()
        .map(crate::commands::status::format_relative_time)
        .unwrap_or_else(|| "never".to_string())
}

fn next_page_command(response: &WorkspaceTokensResponse) -> String {
    let mut parts = vec![
        "boringcache".to_string(),
        "token".to_string(),
        "ls".to_string(),
        response.workspace.slug.clone(),
        format!(
            "--page {}",
            response.pagination.offset / response.pagination.limit + 2
        ),
        format!("--limit {}", response.pagination.limit),
    ];

    if response.filter.include_inactive {
        parts.push("--all".to_string());
    }

    parts.join(" ")
}

fn showing_range(pagination: &crate::api::models::workspace::WorkspacePagination) -> String {
    if pagination.total == 0 || pagination.returned == 0 {
        return format!("0 of {}", pagination.total);
    }

    format!(
        "{}-{} of {}",
        pagination.offset + 1,
        pagination.offset + pagination.returned,
        pagination.total
    )
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@'))
    {
        value.to_string()
    } else {
        format!("{value:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::workspace::{
        WorkspacePagination, WorkspaceSummaryContext, WorkspaceTokensFilter,
        WorkspaceTokensResponse,
    };

    #[test]
    fn parse_token_target_args_supports_implicit_workspace() {
        let (workspace, token_id) =
            parse_token_target_args("revoke", "abcd1234".to_string(), None).unwrap();
        assert_eq!(workspace, None);
        assert_eq!(token_id, "abcd1234");
    }

    #[test]
    fn parse_token_target_args_rejects_missing_token_id_when_workspace_is_present() {
        let err = parse_token_target_args("rotate", "org/ws".to_string(), None).unwrap_err();
        assert!(
            err.to_string()
                .contains("boringcache token rotate <workspace> <token-id>")
        );
    }

    #[test]
    fn resolve_expiration_args_maps_shortcuts() {
        let (preset, custom) = resolve_expiration_args(Some("90d".to_string()), None).unwrap();
        assert_eq!(preset, Some("90_days".to_string()));
        assert_eq!(custom, None);
    }

    #[test]
    fn next_page_command_preserves_all_flag() {
        let response = WorkspaceTokensResponse {
            workspace: WorkspaceSummaryContext {
                name: "testing".to_string(),
                slug: "org/testing".to_string(),
            },
            filter: WorkspaceTokensFilter {
                include_inactive: true,
            },
            pagination: WorkspacePagination {
                limit: 20,
                offset: 20,
                total: 45,
                returned: 20,
                has_more: true,
            },
            tokens: Vec::new(),
        };

        assert_eq!(
            next_page_command(&response),
            "boringcache token ls org/testing --page 3 --limit 20 --all"
        );
    }
}

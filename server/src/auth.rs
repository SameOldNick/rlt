use anyhow::Result;
use async_trait::async_trait;

use crate::error::ServerError;
use crate::CONFIG;

pub enum AuthType {
    None,
    ApiKey,
    Cloudflare,
}

pub fn get_auth_type() -> AuthType {
    match CONFIG.auth_type.as_deref() {
        Some("cloudflare") => AuthType::Cloudflare,
        Some("api_key") => AuthType::ApiKey,
        _ => AuthType::None,
    }
}

pub async fn authenticate_cloudflare(credential: &str, value: &str) -> Result<bool> {
    let account = CONFIG
        .auth_cloudflare_account
        .clone()
        .ok_or(ServerError::InvalidConfig)?;
    let namespace = CONFIG
        .auth_cloudflare_namespace
        .clone()
        .ok_or(ServerError::InvalidConfig)?;
    let email = CONFIG
        .auth_cloudflare_email
        .clone()
        .ok_or(ServerError::InvalidConfig)?;
    let key = CONFIG
        .auth_cloudflare_key
        .clone()
        .ok_or(ServerError::InvalidConfig)?;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/storage/kv/namespaces/{}/values/{}",
            account, namespace, value
        ))
        .header("X-Auth-Email", email)
        .header("X-Auth-Key", key)
        .send()
        .await?
        .text()
        .await?;
    log::info!("{:#?}", resp);

    Ok(credential == resp)
}

pub async fn authenticate_api_key(credential: &str) -> Result<bool> {
    let expected = CONFIG
        .auth_api_key
        .as_deref()
        .ok_or(ServerError::InvalidConfig)?;

    Ok(credential == expected)
}

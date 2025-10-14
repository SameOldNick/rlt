use anyhow::Result;

use crate::error::ServerError;
pub enum AuthType {
    None,
    ApiKey,
    Cloudflare,
}

pub struct AuthCloudflareConfig {
    pub account: String,
    pub namespace: String,
    pub email: String,
    pub key: String,
}

pub struct AuthApiConfig {
    pub api_key: String,
}

pub fn get_auth_type(auth_type: &str) -> AuthType {
    match auth_type {
        "cloudflare" => AuthType::Cloudflare,
        "api_key" => AuthType::ApiKey,
        _ => AuthType::None,
    }
}

pub async fn authenticate_cloudflare(
    config: AuthCloudflareConfig,
    credential: &str,
    value: &str,
) -> Result<bool> {
    let account = config.account;
    let namespace = config.namespace;
    let email = config.email;
    let key = config.key;

    if account.is_empty()
        || namespace.is_empty()
        || email.is_empty()
        || key.is_empty()
        || value.is_empty()
    {
        return Err(ServerError::InvalidConfig.into());
    }

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

pub async fn authenticate_api_key(config: AuthApiConfig, credential: &str) -> Result<bool> {
    let expected = config.api_key;

    Ok(credential == expected)
}

use serde::Deserialize;

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    pub auth_type: Option<String>,
    pub auth_api_key: Option<String>,
    pub auth_cloudflare_account: Option<String>,
    pub auth_cloudflare_namespace: Option<String>,
    pub auth_cloudflare_email: Option<String>,
    pub auth_cloudflare_key: Option<String>,
}

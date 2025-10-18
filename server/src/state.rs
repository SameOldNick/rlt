use std::sync::Arc;
use tokio::sync::Mutex;

use crate::tunnels::Tunnels;

/// App state holds all the client connection and status info.
pub struct State {
    pub tunnels: Arc<Mutex<Tunnels>>,
    pub max_sockets: u8,
    pub secure: bool,
    pub domain: String,
    pub tunnel_port: u16,

    pub endpoint_min_length: usize,
    pub endpoint_max_length: usize,

    pub secret_key_length: usize,

    pub auth_type: String,
    pub auth_api_key: String,
    pub auth_cloudflare_account: String,
    pub auth_cloudflare_namespace: String,
    pub auth_cloudflare_email: String,
    pub auth_cloudflare_key: String,
}

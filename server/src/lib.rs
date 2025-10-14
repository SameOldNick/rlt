//! Start a localtunnel server,
//! request a proxy endpoint at `domain.tld/<your-endpoint>`,
//! user's request then proxied via `<your-endpoint>.domain.tld`.

#[macro_use]
extern crate lazy_static;

use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};

use actix_web::{web, App, HttpServer};
use anyhow::Result;
use dotenv::dotenv;
use hyper::{server::conn::http1, service::service_fn};
use tokio::{net::TcpListener, sync::Mutex, time::timeout};

use crate::api::{api_status, create_tunnel, request_endpoint};
use crate::config::Config;
use crate::proxy::proxy_handler;
use crate::state::{ClientManager, State};

mod api;
mod auth;
mod config;
mod error;
mod proxy;
mod state;

/// The interval between cleanup checks
const CLEANUP_CHECK_INTERVAL: Duration = Duration::from_secs(60);

lazy_static! {
    static ref CONFIG: Config = {
        dotenv().ok();
        envy::from_env::<Config>().unwrap_or_default()
    };
}

pub struct ServerConfig {
    pub domain: String,
    pub api_port: u16,
    pub secure: bool,
    pub max_sockets: u8,
    pub proxy_port: u16,
    pub start_port: u16,
    pub end_port: u16,

    pub auth_type: String,
    pub auth_api_key: String,
    pub auth_cloudflare_account: String,
    pub auth_cloudflare_namespace: String,
    pub auth_cloudflare_email: String,
    pub auth_cloudflare_key: String,
}

/// Start the proxy use low level api from hyper.
/// Proxy endpoint request is served via actix-web.
pub async fn start(config: ServerConfig) -> Result<()> {
    let ServerConfig {
        domain,
        api_port,
        secure,
        max_sockets,
        proxy_port,
        start_port,
        end_port,
        auth_type,
        auth_api_key,
        auth_cloudflare_account,
        auth_cloudflare_namespace,
        auth_cloudflare_email,
        auth_cloudflare_key,
    } = config;
    log::info!("Api server listens at {} {}", &domain, api_port);
    log::info!(
        "Start proxy server at {} {}, options: {} {}",
        &domain,
        proxy_port,
        secure,
        max_sockets
    );

    if auth_type == "none" {
        log::warn!("No authentication is configured, anyone can create proxy endpoint!");
    } else if auth_type == "api_key" {
        if auth_api_key.is_empty() {
            log::error!("Auth type api_key is selected but no api_key provided!");
            return Err(error::ServerError::InvalidConfig.into());
        }
    } else if auth_type == "cloudflare" {
        if auth_cloudflare_account.is_empty()
            || auth_cloudflare_namespace.is_empty()
            || auth_cloudflare_email.is_empty()
            || auth_cloudflare_key.is_empty()
        {
            log::error!(
                "Auth type cloudflare is selected but incomplete cloudflare config provided!"
            );
            return Err(error::ServerError::InvalidConfig.into());
        }
    } else {
        log::error!("Unknown auth type: {}", auth_type);
        return Err(error::ServerError::InvalidConfig.into());
    }

    let manager = Arc::new(Mutex::new(
        ClientManager::new(max_sockets).with_port_range(start_port, end_port),
    ));
    let api_state = web::Data::new(State {
        manager: manager.clone(),
        max_sockets,
        secure,
        domain,

        auth_type,
        auth_api_key: auth_api_key,
        auth_cloudflare_account: auth_cloudflare_account,
        auth_cloudflare_namespace: auth_cloudflare_namespace,
        auth_cloudflare_email: auth_cloudflare_email,
        auth_cloudflare_key: auth_cloudflare_key,
    });

    let proxy_addr: SocketAddr = ([0, 0, 0, 0], proxy_port).into();
    let listener = TcpListener::bind(proxy_addr).await?;
    tokio::spawn(async move {
        loop {
            match timeout(CLEANUP_CHECK_INTERVAL, listener.accept()).await {
                Ok(Ok((stream, _))) => {
                    log::info!("Accepted a new proxy request");

                    let proxy_manager = manager.clone();
                    let service = service_fn(move |req| proxy_handler(req, proxy_manager.clone()));

                    tokio::spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .with_upgrades()
                            .await
                        {
                            log::error!("Failed to serve connection: {:?}", err);
                        }
                    });
                }
                Ok(Err(e)) => log::error!("Failed to accept the request: {:?}", e),
                Err(_) => {
                    // timeout, cleanup old connections
                    let mut manager = manager.lock().await;
                    manager.cleanup().await;
                }
            }
        }
    });

    HttpServer::new(move || {
        App::new()
            .app_data(api_state.clone())
            .service(create_tunnel)
            .service(api_status)
            .service(request_endpoint)
    })
    .bind(("0.0.0.0", api_port))?
    .run()
    .await?;

    Ok(())
}

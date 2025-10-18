//! Start a localtunnel server,
//! request a proxy endpoint at `domain.tld/<your-endpoint>`,
//! user's request then proxied via `<your-endpoint>.domain.tld`.

use clio::Output;
use std::io::Write;
use std::process::{self};
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};

use actix_web::{web, App, HttpServer};
use anyhow::Result;
use dotenv::dotenv;
use hyper::{server::conn::http1, service::service_fn};
use tokio::{net::TcpListener, sync::Mutex, time::timeout};

use crate::api::{api_status, create_tunnel, request_endpoint};
use crate::proxy::proxy_handler;
use crate::state::State;
use crate::tunnels::Tunnels;

mod api;
mod auth;
mod error;
mod proxy;
mod state;
mod tunnel;
mod tunnels;

/// The interval between cleanup checks
const CLEANUP_CHECK_INTERVAL: Duration = Duration::from_secs(60);

pub struct ServerConfig {
    pub daemon: bool,
    pub daemon_user: Option<String>,
    pub daemon_group: Option<String>,
    pub pid_file: Option<Output>,
    pub log: Option<Output>,

    pub endpoint_min_length: usize,
    pub endpoint_max_length: usize,

    pub secret_key_length: usize,

    pub domain: String,
    pub api_port: u16,
    pub secure: bool,
    pub max_sockets: u8,
    pub tunnel_port: u16,
    pub proxy_port: u16,

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
        tunnel_port,

        endpoint_min_length,
        endpoint_max_length,

        secret_key_length,

        daemon,
        daemon_user,
        daemon_group,
        pid_file,
        log,

        auth_type,
        auth_api_key,
        auth_cloudflare_account,
        auth_cloudflare_namespace,
        auth_cloudflare_email,
        auth_cloudflare_key,
    } = config;

    if daemon {
        #[cfg(unix)]
        {
            use daemonize::Daemonize;

            let mut proc_stdout = std::io::stdout();

            let mut daemonize = Daemonize::new();

            if log.is_some() {
                let mut log_value = log.unwrap();

                if log_value.is_local() {
                    let log_file = log_value.get_file();

                    if log_file.is_none() {
                        log::error!("Failed to open log file");
                        process::exit(1);
                    }

                    let output = log_file.as_ref().unwrap();

                    daemonize = daemonize
                        .stdout(output.try_clone().unwrap())
                        .stderr(output.try_clone().unwrap());
                }
            }

            let mut is_pid_file_stdout = false;

            if pid_file.is_some() {
                let pid_value = pid_file.as_ref().unwrap();

                if pid_value.is_local() {
                    let pid_path = pid_value.path();

                    let output = pid_path.to_str().unwrap();

                    daemonize = daemonize.pid_file(output).chown_pid_file(true);
                // Every method except `new` and `start`
                } else if pid_value.is_std() {
                    is_pid_file_stdout = true;
                }
            }

            if daemon_user.is_some() {
                daemonize = daemonize.user(daemon_user.as_deref().unwrap());
            }

            if daemon_group.is_some() {
                daemonize = daemonize.group(daemon_group.as_deref().unwrap());
            }

            match daemonize.start() {
                Ok(_) => {
                    let child_pid = std::process::id();

                    if is_pid_file_stdout {
                        pid_file
                            .unwrap()
                            .write(child_pid.to_string().as_bytes())
                            .unwrap();
                    }

                    log::info!("Success, daemonized with pid {}", child_pid);

                    log::info!("Server daemonized successfully");
                }
                Err(e) => {
                    log::error!("Error, {}", e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(unix))]
        {
            log::error!("Daemon mode is only supported on Unix systems.");
            std::process::exit(1);
        }
    }

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

    // make tunnels an Arc<Mutex<Tunnels>> so we can mutate it from async tasks
    let tunnels = Arc::new(tokio::sync::Mutex::new(Tunnels::new(
        tunnel_port,
        max_sockets as usize,
    )));

    // spawn the listener task which locks the mutex and runs listen()
    let tunnels_for_listen = Arc::clone(&tunnels);
    tokio::spawn(async move {
        let mut guard = tunnels_for_listen.lock().await;
        if let Err(err) = guard.listen().await {
            log::error!("tunnels.listen() failed: {:?}", err);
        }
        // guard dropped here
    });

    /*let manager = Arc::new(Mutex::new(
        ClientManager::new(max_sockets).with_port_range(start_port, end_port),
    ));*/
    let api_state = web::Data::new(State {
        tunnels: tunnels.clone(),
        max_sockets,
        secure,
        domain,

        tunnel_port,

        endpoint_min_length,
        endpoint_max_length,

        secret_key_length: secret_key_length,

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

                    let tunnels_for_service = Arc::clone(&tunnels);

                    let service = service_fn(move |req| {
                        let tunnels = Arc::clone(&tunnels_for_service);
                        async move { proxy_handler(req, tunnels).await }
                    });

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
                    //tunnels.shutdown().await;
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

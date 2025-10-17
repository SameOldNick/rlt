use std::{collections::HashMap, io::Read};

use anyhow::Result;
use clap::{Parser, Subcommand};
use clio::*;
use config::Config;
use localtunnel_client::{broadcast, open_tunnel, ClientConfig};
use localtunnel_server::{start, ServerConfig};
use tokio::signal;

#[path = "config.rs"]
mod cli_config;

#[derive(Parser)]
#[clap(author, version, about)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Builds connection between remote proxy server and local api.
    Client {
        /// Address of proxy server
        #[arg(long)]
        host: String,
        /// Subdomain of the proxied url
        #[arg(long)]
        subdomain: String,
        /// The local host to expose.
        #[arg(long, default_value = "127.0.0.1")]
        local_host: String,
        /// The local port to expose.
        #[arg(short, long)]
        port: u16,
        /// Max connections allowed to server.
        #[arg(long, default_value = "10")]
        max_conn: u8,
        #[arg(long)]
        credential: Option<String>,
    },

    /// Starts proxy server to accept user connections and proxy setup connection.
    Server {
        /// Path to configuration file.
        #[arg(long, short = 'c', value_parser)]
        config: Option<Input>,

        /// Run the server as a daemon.
        #[arg(long, default_value_t = false)]
        daemon: bool,

        /// User to run the daemon as (only when run as daemon).
        #[arg(long)]
        daemon_user: Option<String>,
        /// Group to run the daemon as (only when run as daemon).
        #[arg(long)]
        daemon_group: Option<String>,

        /// Minimum length of the endpoint.
        #[arg(long, default_value = "8")]
        endpoint_min_length: usize,
        /// Maximum length of the endpoint.
        #[arg(long, default_value = "32")]
        endpoint_max_length: usize,

        /// Length of the secret key.
        #[arg(long, default_value = "32")]
        secret_key_length: usize,

        /// Path to the PID file.
        #[arg(long)]
        pid_file: Option<Output>,

        /// Path to the log file.
        #[arg(long)]
        log: Option<Output>,

        /// Domain name of the proxy server, required if use subdomain like lt.example.com.
        #[arg(long)]
        domain: Option<String>,
        /// The port to accept initialize proxy endpoint.
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// The flag to indicate proxy over https.
        #[arg(long)]
        secure: bool,
        /// Maximum number of tcp sockets each client to establish at one time.
        #[arg(long, default_value = "10")]
        max_sockets: u8,
        /// The port to accept user request for proxying.
        #[arg(long, default_value = "3001")]
        proxy_port: u16,
        /// Starting port of the range to allocate for proxying.
        #[arg(short, long, default_value = "0")]
        start_port: u16,
        /// Ending port of the range to allocate for proxying.
        #[arg(short, long, default_value = "0")]
        end_port: u16,

        /// Authentication type, can be none, api_key or cloudflare.
        #[arg(long, default_value = "none")]
        auth_type: String,

        /// API key for auth_type api_key.
        #[arg(long)]
        auth_api_key: Option<String>,

        /// Cloudflare account id for auth_type cloudflare.
        #[arg(long)]
        auth_cloudflare_account: Option<String>,
        /// Cloudflare namespace for auth_type cloudflare.
        #[arg(long)]
        auth_cloudflare_namespace: Option<String>,
        /// Cloudflare email for auth_type cloudflare.
        #[arg(long)]
        auth_cloudflare_email: Option<String>,
        /// Cloudflare api key for auth_type cloudflare.
        #[arg(long)]
        auth_cloudflare_key: Option<String>,
    },
}

#[derive(serde::Deserialize)]
struct ConfigYaml {
    domain: String,
    port: u16,

    endpoint_min_length: usize,
    endpoint_max_length: usize,

    secret_key_length: usize,

    secure: bool,
    max_sockets: Option<u8>,
    proxy_port: u16,
    start_port: Option<u16>,
    end_port: Option<u16>,

    auth_type: String,
    auth_api_key: Option<String>,
    auth_cloudflare_account: Option<String>,
    auth_cloudflare_namespace: Option<String>,
    auth_cloudflare_email: Option<String>,
    auth_cloudflare_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    //config::setup();
    log::info!("Run localtunnel CLI!");

    cli_config::setup();

    let command = Cli::parse().command;

    match command {
        Command::Client {
            host,
            subdomain,
            local_host,
            port,
            max_conn,
            credential,
        } => {
            let (notify_shutdown, _) = broadcast::channel(1);
            let config = ClientConfig {
                server: Some(host),
                subdomain: Some(subdomain),
                local_host: Some(local_host),
                local_port: port,
                shutdown_signal: notify_shutdown.clone(),
                max_conn,
                credential,
            };
            let result = open_tunnel(config).await?;
            log::info!("Tunnel url: {:?}", result);

            signal::ctrl_c().await?;
            log::info!("Quit");
        }
        Command::Server {
            config,
            daemon,
            daemon_user,
            daemon_group,
            pid_file,
            log,
            endpoint_min_length,
            endpoint_max_length,
            secret_key_length,
            domain,
            port,
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
        } => {
            let mut file_domain: Option<String> = None;

            if let Some(mut input) = config {
                log::info!("Load configuration from file");

                let mut contents = String::new();
                input.read_to_string(&mut contents)?;

                let settings = Config::builder()
                    .add_source(config::File::from_str(&contents, config::FileFormat::Yaml))
                    // Add in settings from the environment (with a prefix of LT)
                    // Eg.. `LT_DEBUG=1 ./target/app` would set the `debug` key
                    .add_source(config::Environment::with_prefix("LT"))
                    .build()
                    .unwrap();

                // Print out our settings (as a HashMap)
                let map = settings.try_deserialize::<ConfigYaml>().unwrap();

                // try to get domain from config file
                file_domain = map.domain.into();

                if file_domain.is_none() || file_domain.as_ref().unwrap().is_empty() {
                    log::error!("Domain must be provided in the config file!");
                    return Err(anyhow::anyhow!(
                        "Domain must be provided in the config file!"
                    ));
                }

                let server_config = ServerConfig {
                    domain: file_domain.clone().unwrap(),

                    endpoint_min_length: map.endpoint_min_length,
                    endpoint_max_length: map.endpoint_max_length,

                    secret_key_length: map.secret_key_length,

                    daemon,
                    daemon_user,
                    daemon_group,
                    pid_file,
                    log,

                    api_port: map.port,
                    secure: map.secure,
                    max_sockets: if map.max_sockets.is_some() {
                        map.max_sockets.unwrap()
                    } else {
                        max_sockets
                    },
                    proxy_port: map.proxy_port,
                    start_port: if map.start_port.is_some() {
                        map.start_port.unwrap()
                    } else {
                        start_port
                    },
                    end_port: if map.end_port.is_some() {
                        map.end_port.unwrap()
                    } else {
                        end_port
                    },
                    auth_type: map.auth_type,
                    auth_api_key: map.auth_api_key.unwrap_or_default(),
                    auth_cloudflare_account: map.auth_cloudflare_account.unwrap_or_default(),
                    auth_cloudflare_namespace: map.auth_cloudflare_namespace.unwrap_or_default(),
                    auth_cloudflare_email: map.auth_cloudflare_email.unwrap_or_default(),
                    auth_cloudflare_key: map.auth_cloudflare_key.unwrap_or_default(),
                };

                start(server_config).await?;
            } else {
                if domain.is_none() || domain.as_ref().unwrap().is_empty() {
                    log::error!("Domain must be provided in the config file!");
                    return Err(anyhow::anyhow!(
                        "Domain must be provided in the config file!"
                    ));
                }

                let server_config = ServerConfig {
                    domain: domain.clone().unwrap(),
                    endpoint_min_length,
                    endpoint_max_length,

                    secret_key_length,

                    daemon,
                    daemon_user,
                    daemon_group,

                    pid_file,
                    log,

                    api_port: port,
                    secure,
                    max_sockets,
                    proxy_port,
                    start_port,
                    end_port,
                    auth_type,
                    auth_api_key: auth_api_key.as_deref().unwrap_or_default().to_string(),
                    auth_cloudflare_account: auth_cloudflare_account
                        .as_deref()
                        .unwrap_or_default()
                        .to_string(),
                    auth_cloudflare_namespace: auth_cloudflare_namespace
                        .as_deref()
                        .unwrap_or_default()
                        .to_string(),
                    auth_cloudflare_email: auth_cloudflare_email
                        .as_deref()
                        .unwrap_or_default()
                        .to_string(),
                    auth_cloudflare_key: auth_cloudflare_key
                        .as_deref()
                        .unwrap_or_default()
                        .to_string(),
                };

                start(server_config).await?;
            }
        }
    }

    Ok(())
}

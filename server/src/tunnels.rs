use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::tunnel::Tunnel;
use serde_json::Value;
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Interest},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock},
    task::JoinHandle,
};

// See https://tldp.org/HOWTO/html_single/TCP-Keepalive-HOWTO to understand how keepalive work.
const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(not(target_os = "windows"))]
const TCP_KEEPALIVE_RETRIES: u32 = 5;

pub struct Allowed {
    pub secret_key: String,
    pub endpoint: String,
}

pub struct Tunnels {
    pub port: u16,
    pub max_per_endpoint: usize,
    pub allowed: Arc<AsyncRwLock<HashMap<String, Arc<AsyncMutex<Allowed>>>>>,
    pub tunnels: Arc<AsyncMutex<Vec<Tunnel>>>,

    accept_handle: Option<JoinHandle<()>>,
}

impl Tunnels {
    pub fn new(port: u16, max_per_endpoint: usize) -> Self {
        Tunnels {
            port,
            max_per_endpoint,
            tunnels: Arc::new(AsyncMutex::new(Vec::new())),
            allowed: Arc::new(AsyncRwLock::new(HashMap::new())),
            accept_handle: None,
        }
    }

    pub async fn add_allowed(&mut self, key: String, endpoint: String) {
        let allowed = Allowed {
            secret_key: key.clone(),
            endpoint,
        };

        let mut w = self.allowed.write().await;

        w.insert(key, Arc::new(AsyncMutex::new(allowed)));
    }

    pub async fn take(&mut self, endpoint: &str) -> Option<Tunnel> {
        let mut tunnels = self.tunnels.lock().await;

        loop {
            if tunnels.is_empty() {
                break;
            }

            if let Some(pos) = tunnels.iter().position(|t| t.endpoint == endpoint) {
                let tunnel = tunnels.remove(pos);

                if socket_is_writable(&tunnel.stream).await {
                    return Some(tunnel);
                }
            } else {
                break;
            }
        }

        None
    }

    pub async fn listen(&mut self) -> Result<(), std::io::Error> {
        let port = self.port;

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        let allowed = Arc::clone(&self.allowed);
        let tunnels = Arc::clone(&self.tunnels);

        let max_per_endpoint = self.max_per_endpoint;

        self.accept_handle = Some(tokio::spawn(async move {
            loop {
                log::info!("Waiting for new tunnel connections on port {}", port);

                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        log::info!("Accepted a new tunnel connection");

                        // Handle the tunnel connection
                        if let Err(e) = configure_socket(&stream).await {
                            log::warn!("failed to configure socket: {}", e);
                            // drop this connection and continue accepting others
                            continue;
                        }

                        let secret_key = gather_secret(&mut stream).await;

                        match secret_key {
                            Ok(key) => {
                                log::info!("Received secret key: {}", key);

                                let map = allowed.read().await;

                                if let Some(allowed_arc) = map.get(&key).cloned() {
                                    // lock the Allowed to access endpoint
                                    let allowed_guard = allowed_arc.lock().await;
                                    let endpoint = allowed_guard.endpoint.clone();

                                    log::info!("Authorized tunnel for endpoint: {}", endpoint);

                                    let tunnels_guard = tunnels.lock().await;
                                    let mut current = 0usize;
                                    for t in tunnels_guard.iter() {
                                        if t.endpoint == endpoint {
                                            if socket_is_writable(&t.stream).await {
                                                current += 1;
                                            }
                                        }
                                    }

                                    if current >= max_per_endpoint {
                                        log::warn!(
                                            "Endpoint '{}' reached max sockets {}/{} - rejecting",
                                            endpoint,
                                            current,
                                            max_per_endpoint
                                        );
                                        // politely notify client and drop connection
                                        if let Err(err) =
                                            send_auth_failure(&mut stream, "Too many connections")
                                                .await
                                        {
                                            log::warn!("failed to send overflow response: {}", err);
                                        }
                                        continue;
                                    }

                                    if let Err(e) = send_auth_success(&mut stream).await {
                                        log::warn!("failed to send auth success: {}", e);
                                        continue;
                                    }

                                    // Put socket into shared pool
                                    let mut tunnels_guard = tunnels.lock().await;
                                    tunnels_guard.push(Tunnel::new(stream, endpoint));
                                } else {
                                    log::warn!("Unauthorized tunnel attempt with key: {}", key);
                                    let _ =
                                        send_auth_failure(&mut stream, "Unauthorized access").await;
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to gather secret key: {}", e);
                                if let Err(err) =
                                    send_auth_failure(&mut stream, "Failed to gather secret key")
                                        .await
                                {
                                    log::warn!("failed to send auth failure: {}", err);
                                }
                                // Optionally close the connection or send an error response.
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error accepting tunnel connection: {}", e);
                    }
                }
            }
        }));

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        for tunnel in self.tunnels.lock().await.iter_mut() {
            if let Err(e) = tunnel.stream.shutdown().await {
                log::warn!("failed to shutdown tunnel stream: {}", e);
            }
        }

        if let Some(handle) = self.accept_handle.take() {
            handle.abort();
            log::info!("Tunnel listener on port {} has been shut down.", self.port);

            self.accept_handle = None;
        }
    }
}

impl Drop for Tunnels {
    fn drop(&mut self) {
        self.shutdown();
    }
}

async fn gather_secret(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = BufReader::new(stream);
    let mut line = String::new();

    // read one line with a reasonable size limit
    match buf.read_line(&mut line).await {
        Ok(0) => return Err("connection closed before auth".into()),
        Ok(n) if n > 10_000 => return Err("auth payload too large".into()),
        Ok(_) => {}
        Err(e) => return Err(format!("io error: {}", e)),
    }

    // Note: because we wrapped the stream in BufReader, we need to retrieve the inner stream back.
    // If callers rely on the original TcpStream after this, refactor to read into a buffer without
    // taking ownership, or implement a framed protocol on top.
    let parsed: Value = serde_json::from_str(&line).map_err(|e| format!("json error: {}", e))?;

    let type_is_auth = parsed
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        == "auth";
    let has_key = parsed.get("key").is_some();

    if !type_is_auth || !has_key {
        return Err("The type and key is missing".into());
    }

    let key = parsed
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    Ok(key.to_string())
}

async fn send_auth_success(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    stream.write_all("AUTH_OK\n".as_bytes()).await?;
    Ok(())
}

async fn send_auth_failure(stream: &mut TcpStream, reason: &str) -> Result<(), std::io::Error> {
    let response = serde_json::json!({
        "status": "error",
        "reason": reason
    });
    let response_str = response.to_string() + "\n";
    stream.write_all(response_str.as_bytes()).await?;
    Ok(())
}

async fn configure_socket(stream: &tokio::net::TcpStream) -> Result<(), std::io::Error> {
    let ka = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    #[cfg(not(target_os = "windows"))]
    let ka = ka.with_retries(TCP_KEEPALIVE_RETRIES);

    let sf = SockRef::from(&stream);
    if let Err(err) = sf.set_tcp_keepalive(&ka) {
        log::warn!("failed to enable TCP keepalive: {err}");
    }

    Ok(())
}

async fn socket_is_writable(socket: &TcpStream) -> bool {
    socket
        .ready(Interest::WRITABLE)
        .await
        // `is_write_closed` is set to `true` when keepalive times out
        .map(|ready| !ready.is_write_closed())
        .unwrap_or_default()
}

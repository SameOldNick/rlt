use std::sync::Arc;

use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::{self, Next};
use actix_web::{get, post, route, web, Error, HttpResponse, Responder};
use anyhow::Result;
use fake::Fake;
use rand::rngs::OsRng;
use rand::{Rng, TryRngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{
    authenticate_api_key, authenticate_cloudflare, get_auth_type, AuthApiConfig,
    AuthCloudflareConfig,
};
use crate::state::State;

#[get("/api/status")]
pub async fn api_status() -> impl Responder {
    let status = ApiStatus {
        tunnels_count: 0,
        tunels: "kaichao".to_string(),
    };

    HttpResponse::Ok().json(status)
}

#[route(
    "/",
    method = "GET",
    method = "POST",
    wrap = "middleware::from_fn(auth_mw)"
)]
pub async fn create_tunnel(state: web::Data<State>) -> impl Responder {
    let endpoint = generate_endpoint(
        state.endpoint_min_length.try_into().unwrap(),
        state.endpoint_max_length.try_into().unwrap(),
    );

    create_proxy_for(&endpoint, &state).await
}

/// Request proxy endpoint
#[post("/{endpoint}")]
pub async fn request_endpoint(
    endpoint: web::Path<String>,
    state: web::Data<State>,
) -> impl Responder {
    create_proxy_for(&endpoint, &state).await
}

fn generate_endpoint(min_length: u32, mut max_length: u32) -> String {
    // sanitize lengths
    if max_length == 0 {
        max_length = 32;
    }

    let length = if min_length == max_length {
        min_length as usize
    } else {
        let mut rng = rand::rng();
        rng.random_range(min_length as usize..=max_length as usize)
    };

    let bytes_needed = (length + 1) / 2;
    let mut rng = OsRng;
    let mut buffer = vec![0u8; bytes_needed]; // Generate random bytes
    rng.try_fill_bytes(&mut buffer)
        .expect("Failed to generate random bytes");

    let mut hex_string = String::new();
    for byte in buffer {
        hex_string.push_str(&format!("{:02x}", byte));
    }

    hex_string.truncate(length); // Ensure the string is of the desired length

    hex_string
}

// shared logic used by both handlers
async fn auth_mw(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    // pre-processing
    let state = req
        .app_data::<web::Data<State>>()
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("State not found"))?;

    let endpoint = req.match_info().get("endpoint").unwrap_or("");

    let auth_header_value = req
        .headers()
        .get("Authorization")
        .and_then(|val| val.to_str().ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, char::is_whitespace);
            match (parts.next(), parts.next()) {
                (Some(scheme), Some(token)) if scheme.eq_ignore_ascii_case("bearer") => {
                    Some(token.trim().to_string())
                }
                _ => None,
            }
        })
        .unwrap_or_default();

    let credential = req
        .query_string()
        .split('&')
        .find_map(|pair| {
            let mut iter = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                if key == "credential" {
                    return Some(value.to_string());
                }
            }
            None
        })
        .unwrap_or_default();

    // Check auth and only return on failure. On success continue to create the proxy.
    match get_auth_type(state.auth_type.as_str()) {
        crate::auth::AuthType::None => (),
        crate::auth::AuthType::ApiKey => {
            match authenticate_api_key(
                AuthApiConfig {
                    api_key: state.auth_api_key.clone(),
                },
                &auth_header_value,
            )
            .await
            {
                Ok(true) => (), // authenticated — continue
                Ok(false) => {
                    let resp = HttpResponse::BadRequest()
                        .body("Error: Authorization value is not valid.".to_string())
                        .map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
                Err(err) => {
                    log::error!("Server error: {:?}", err);
                    let resp = HttpResponse::InternalServerError()
                        .body(format!("Server Error: {:?}", err))
                        .map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            }
        }

        crate::auth::AuthType::Cloudflare => {
            match authenticate_cloudflare(
                AuthCloudflareConfig {
                    account: state.auth_cloudflare_account.clone(),
                    namespace: state.auth_cloudflare_namespace.clone(),
                    email: state.auth_cloudflare_email.clone(),
                    key: state.auth_cloudflare_key.clone(),
                },
                &credential,
                endpoint,
            )
            .await
            {
                Ok(true) => (), // authenticated — continue
                Ok(false) => {
                    let resp = HttpResponse::BadRequest()
                        .body("Error: credential is not valid.".to_string())
                        .map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
                Err(err) => {
                    log::error!("Server error: {:?}", err);
                    let resp = HttpResponse::InternalServerError()
                        .body(format!("Server Error: {:?}", err))
                        .map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            }
        }
    };

    // invoke the wrapped middleware or service
    let res = next.call(req).await?;

    // post-processing

    Ok(res)
}

async fn create_proxy_for(endpoint: &str, state: &web::Data<State>) -> HttpResponse {
    log::debug!("Create/Request proxy endpoint, {}", endpoint);

    match validate_endpoint(endpoint) {
        Ok(true) => (),
        Ok(false) => {
            return HttpResponse::BadRequest().body(
                "Request subdomain is invalid, only chars in lowercase and numbers are allowed",
            )
        }
        Err(err) => {
            return HttpResponse::InternalServerError().body(format!("Server Error: {:?}", err))
        }
    }

    let secret_key = Arc::new(generate_secret_key(state.secret_key_length as usize));

    let mut tunnels = state.tunnels.lock().await;

    tunnels
        .add_allowed(secret_key.clone().to_string(), endpoint.to_string())
        .await;

    let schema = if state.secure { "https" } else { "http" };
    let info = ProxyInfo {
        id: endpoint.to_string(),
        port: state.tunnel_port,
        max_conn_count: state.max_sockets,
        url: format!("{}://{}.{}", schema, endpoint, state.domain),
        secret_key: secret_key.clone().to_string(),
    };

    log::debug!("Proxy info, {:?}", info);
    HttpResponse::Ok().json(info)
}

fn generate_secret_key(length: usize) -> String {
    let bytes_needed = (length + 1) / 2;
    let mut rng = OsRng;
    let mut buffer = vec![0u8; bytes_needed]; // Generate random bytes
    rng.try_fill_bytes(&mut buffer)
        .expect("Failed to generate random bytes");

    let mut hex_string = String::new();
    for byte in buffer {
        hex_string.push_str(&format!("{:02x}", byte));
    }

    hex_string.truncate(length); // Ensure the string is of the desired length

    hex_string
}

fn validate_endpoint(endpoint: &str) -> Result<bool> {
    // Don't allow A-Z uppercase since it will convert to lowercase in browser
    let re = Regex::new("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")?;
    Ok(re.is_match(endpoint))
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiStatus {
    tunnels_count: u16,
    tunels: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxyInfo {
    id: String,
    port: u16,
    max_conn_count: u8,
    url: String,
    secret_key: String,
}

#[cfg(test)]
mod tests {
    use crate::api::validate_endpoint;

    #[test]
    fn validate_endpoint_works() {
        let endpoints = [
            "demo",
            "123",
            "did-key-zq3shkkuzlvqefghdgzgfmux8vgkgvwsla83w2oekhzxocw2n",
        ];

        for endpoint in endpoints {
            assert!(validate_endpoint(endpoint).unwrap());
        }
    }
}

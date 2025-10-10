use crate::config::AUTH_TOKEN;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, EXPIRES, PRAGMA},
    Method, Request, Response, StatusCode,
};
use serde_json::Value;
use std::net::SocketAddr;

pub fn unix_time() -> u64 {
    Utc::now().timestamp() as u64
}

pub async fn extract_json_body(req: Request<Incoming>) -> Result<Value, String> {
    let body = req
        .into_body()
        .collect()
        .await
        .map_err(|_| "Failed to read body")?
        .to_bytes();

    if body.is_empty() {
        return Err("Empty body".to_string());
    }

    serde_json::from_slice(&body).map_err(|_| "Invalid JSON".to_string())
}

pub fn json_response(v: Value, status: StatusCode) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub fn bytes_download_response(filename: &str, bytes: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

pub fn unauthorized() -> Response<Full<Bytes>> {
    json_response(
        serde_json::json!({"error": "Unauthorized"}),
        StatusCode::UNAUTHORIZED,
    )
}

pub fn is_authorized(req: &Request<Incoming>) -> bool {
    if let Some(h) = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
    {
        if let Some(token) = h.strip_prefix("Bearer ") {
            return token == AUTH_TOKEN;
        }
    }
    false
}

pub fn log_request(method: &Method, endpoint: &str, remote: &SocketAddr, _data: Option<&Value>) {
    // ログは重要なエンドポイントのみに制限
    if endpoint.contains("/api/upload") || endpoint.contains("/api/register") {
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S");
        println!("[{}] {} {} - {}", timestamp, method, endpoint, remote);
    }
}

pub fn parse_query_param(req: &Request<Incoming>, key: &str) -> Option<String> {
    req.uri().query()?.split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        match (parts.next()?, parts.next()) {
            (k, Some(v)) if k == key => Some(v.to_string()),
            (k, None) if k == key => Some(String::new()),
            _ => None,
        }
    })
}

pub fn parse_query_bool(req: &Request<Incoming>, key: &str) -> bool {
    matches!(
        parse_query_param(req, key).as_deref(),
        Some("1" | "true" | "yes")
    )
}

pub fn parse_query_u64(req: &Request<Incoming>, key: &str, default: u64) -> u64 {
    parse_query_param(req, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn html_response(html: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(
            CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header(PRAGMA, "no-cache")
        .header(EXPIRES, "0")
        .body(Full::new(Bytes::from(html.to_owned())))
        .unwrap()
}

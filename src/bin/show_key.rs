use std::env;
use std::fs;
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <encryption_key.dat>", args[0]);
        eprintln!("Example: {} encryption_key.dat", args[0]);
        return Ok(());
    }

    let key_file = &args[1];
    
    println!("🔑 キーファイル表示: {}", key_file);

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

    // キー詳細表示
    println!("\n=== AES-256 暗号化キー詳細 ===");
    
    // Base64表示
    let key_b64 = general_purpose::STANDARD.encode(&key);
    let nonce_b64 = general_purpose::STANDARD.encode(&nonce);
    
    println!("🔐 キー (Base64): {}", key_b64);
    println!("🎲 Nonce (Base64): {}", nonce_b64);
    
    // 16進数表示
    println!("🔐 キー (Hex): {}", key.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("🎲 Nonce (Hex): {}", nonce.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    
    // サイズ情報
    println!("📏 キーサイズ: {} bytes (AES-256)", key.len());
    println!("📏 Nonceサイズ: {} bytes (GCM)", nonce.len());
    
    // セキュリティ情報
    println!("\n=== セキュリティ情報 ===");
    println!("🔒 暗号化方式: AES-256-GCM");
    println!("🛡️ 認証付き暗号化: はい");
    println!("⚠️ 注意: このキーは機密情報です。安全に保管してください。");
    
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
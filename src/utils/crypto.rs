// 暗号化機能モジュール
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use rand::RngCore;
use crate::{RatResult, RatError};

// 非推奨関数を削除：generate_key_pair + encrypt_data_with_key を直接使用

pub fn encrypt_data_with_key(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> RatResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| RatError::Encryption(format!("Encryption failed: {:?}", e)))
}

pub fn generate_key_pair() -> ([u8; 32], [u8; 12]) {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut key);
    rand::rng().fill_bytes(&mut nonce);
    (key, nonce)
}
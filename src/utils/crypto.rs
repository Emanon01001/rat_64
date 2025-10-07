// 暗号化機能モジュール
use crate::{AoiError, AoiResult};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub fn encrypt_data_with_key(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> AoiResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| AoiError::Encryption(format!("Encryption failed: {:?}", e)))
}

pub fn generate_key_pair() -> ([u8; 32], [u8; 12]) {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut key).expect("Failed to generate random key");
    getrandom::fill(&mut nonce).expect("Failed to generate random nonce");
    (key, nonce)
}

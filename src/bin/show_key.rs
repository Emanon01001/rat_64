use std::env;
use std::fs::File;
use std::io::Read;
use serde::{Serialize, Deserialize};
use rmp_serde::{decode::from_slice as from_msgpack_slice};
use base64::{engine::general_purpose, Engine as _};

#[derive(Serialize, Deserialize, Debug)]
struct KeyData {
    key: String,
    nonce: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <key.bin>", args[0]);
        std::process::exit(1);
    }

    // Load the key file
    let mut file = File::open(&args[1]).expect("Failed to open the key file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("File read error");

    // Decode MessagePack
    let key_data: KeyData = from_msgpack_slice(&buffer)
        .expect("Failed to decode the key file");

    println!("=== AES-256 key details ===");
    println!("Key (Base64): {}", key_data.key);
    println!("Nonce (Base64): {}", key_data.nonce);
    
    // Also display the values as raw bytes
    let key_bytes = general_purpose::STANDARD.decode(&key_data.key).unwrap();
    let nonce_bytes = general_purpose::STANDARD.decode(&key_data.nonce).unwrap();
    
    println!("Key length: {} bytes", key_bytes.len());
    println!("Nonce length: {} bytes", nonce_bytes.len());
    
    println!("Key (hex): {}", key_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("Nonce (hex): {}", nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}
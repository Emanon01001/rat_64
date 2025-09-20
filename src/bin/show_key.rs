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
        println!("使用法: {} <key.bin>", args[0]);
        std::process::exit(1);
    }

    // キーファイル読み込み
    let mut file = File::open(&args[1]).expect("キーファイルを開けませんでした");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("ファイル読み込みエラー");

    // MessagePackデコード
    let key_data: KeyData = from_msgpack_slice(&buffer)
        .expect("キーファイルのデコードエラー");

    println!("=== AES-256キー情報 ===");
    println!("キー (Base64): {}", key_data.key);
    println!("Nonce (Base64): {}", key_data.nonce);
    
    // バイナリ形式でも表示
    let key_bytes = general_purpose::STANDARD.decode(&key_data.key).unwrap();
    let nonce_bytes = general_purpose::STANDARD.decode(&key_data.nonce).unwrap();
    
    println!("キー長: {} バイト", key_bytes.len());
    println!("Nonce長: {} バイト", nonce_bytes.len());
    
    println!("キー (16進数): {}", key_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("Nonce (16進数): {}", nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}
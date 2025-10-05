// Direct Syscall Test Binary
// WindowsカーネルAPIを直接呼び出すテストプログラム

#![cfg(target_os = "windows")]

use std::{
    ffi::c_void,
    mem,
};

// NT API構造体定義
#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)] // Windows API命名規則に従う
struct SYSTEM_BASIC_INFORMATION {
    reserved: u32,
    timer_resolution: u32,
    page_size: u32,
    number_of_physical_pages: u32,
    lowest_physical_page_number: u32,
    highest_physical_page_number: u32,
    allocation_granularity: u32,
    minimum_user_mode_address: usize,
    maximum_user_mode_address: usize,
    active_processors_affinity_mask: usize,
    number_of_processors: u8,
}

#[repr(C)]
#[derive(Debug)]
#[allow(dead_code, non_camel_case_types)] // テスト用構造体・Windows API命名規則
struct CLIENT_ID {
    unique_process: *mut c_void,
    unique_thread: *mut c_void,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)] // Windows API命名規則に従う
struct PROCESS_BASIC_INFORMATION {
    exit_status: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

// システム情報クラス
const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

// NTSTATUSコード
const STATUS_SUCCESS: i32 = 0;
#[allow(dead_code)] // 将来の拡張用
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

// Direct Syscall実装
#[cfg(feature = "direct-syscall")]
mod direct_syscall {
    use super::*;
    
    // NtQuerySystemInformation のシステムコール番号 (Windows 10/11)
    const SYSCALL_NT_QUERY_SYSTEM_INFORMATION: u16 = 0x0036;
    const SYSCALL_NT_QUERY_INFORMATION_PROCESS: u16 = 0x0013;
    
    /// x64 Direct Syscall実行
    #[cfg(target_arch = "x86_64")]
    unsafe fn execute_syscall(
        syscall_number: u16,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        _arg5: usize, // 現在未使用
    ) -> i32 {
        let result: i32;
        std::arch::asm!(
            "mov r10, rcx",           // システムコール規約: r10 = rcx
            "mov eax, {syscall_num:e}", // システムコール番号をeaxにセット（32bit）
            "syscall",                // カーネルモードに切り替え
            syscall_num = in(reg) syscall_number as u32,
            inout("rcx") arg1 => _,   // 第1引数
            in("rdx") arg2,           // 第2引数
            in("r8") arg3,            // 第3引数
            in("r9") arg4,            // 第4引数
            out("eax") result,        // 戻り値
            out("r10") _,             // クリーンアップ
            out("r11") _,             // クリーンアップ
            clobber_abi("system"),
        );
        result
    }
    
    /// Direct Syscall: NtQuerySystemInformation
    pub unsafe fn nt_query_system_information_direct(
        info_class: u32,
        info: *mut c_void,
        info_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        execute_syscall(
            SYSCALL_NT_QUERY_SYSTEM_INFORMATION,
            info_class as usize,
            info as usize,
            info_length as usize,
            return_length as usize,
            0
        )
    }
    
    /// Direct Syscall: NtQueryInformationProcess
    pub unsafe fn nt_query_information_process_direct(
        process_handle: *mut c_void,
        info_class: u32,
        info: *mut c_void,
        info_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        execute_syscall(
            SYSCALL_NT_QUERY_INFORMATION_PROCESS,
            process_handle as usize,
            info_class as usize,
            info as usize,
            info_length as usize,
            return_length as usize
        )
    }
}

#[cfg(not(feature = "direct-syscall"))]
mod direct_syscall {
    use super::*;
    
    pub unsafe fn nt_query_system_information_direct(
        _info_class: u32,
        _info: *mut c_void,
        _info_length: u32,
        _return_length: *mut u32,
    ) -> i32 {
        eprintln!("❌ Direct Syscall機能が無効です。--features direct-syscall でビルドしてください");
        -1
    }
    
    pub unsafe fn nt_query_information_process_direct(
        _process_handle: *mut c_void,
        _info_class: u32,
        _info: *mut c_void,
        _info_length: u32,
        _return_length: *mut u32,
    ) -> i32 {
        eprintln!("❌ Direct Syscall機能が無効です。--features direct-syscall でビルドしてください");
        -1
    }
}

// Windows API比較用
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
    
    fn NtQueryInformationProcess(
        ProcessHandle: *mut c_void,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Direct Syscall vs Windows API パフォーマンステスト");
    println!("============================================");
    
    // システム基本情報テスト
    test_system_information()?;
    
    // プロセス情報テスト  
    test_process_information()?;
    
    // パフォーマンス比較
    benchmark_performance()?;
    
    Ok(())
}

fn test_system_information() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 システム基本情報テスト");
    println!("-------------------------");
    
    unsafe {
        let mut system_info: SYSTEM_BASIC_INFORMATION = mem::zeroed();
        let mut return_length: u32 = 0;
        
        // Direct Syscall版
        println!("🔧 Direct Syscall実行中...");
        let status = direct_syscall::nt_query_system_information_direct(
            SYSTEM_BASIC_INFORMATION_CLASS,
            &mut system_info as *mut _ as *mut c_void,
            mem::size_of::<SYSTEM_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
        
        if status == STATUS_SUCCESS {
            println!("✅ Direct Syscall成功!");
            println!("   📄 ページサイズ: {} bytes", system_info.page_size);
            println!("   🧮 プロセッサ数: {}", system_info.number_of_processors);
            println!("   💾 物理ページ数: {}", system_info.number_of_physical_pages);
        } else {
            println!("❌ Direct Syscall失敗: 0x{:08X}", status);
        }
        
        // Windows API版（比較用）
        let mut system_info_api: SYSTEM_BASIC_INFORMATION = mem::zeroed();
        let mut return_length_api: u32 = 0;
        
        println!("🔧 Windows API実行中...");
        let status_api = NtQuerySystemInformation(
            SYSTEM_BASIC_INFORMATION_CLASS,
            &mut system_info_api as *mut _ as *mut c_void,
            mem::size_of::<SYSTEM_BASIC_INFORMATION>() as u32,
            &mut return_length_api,
        );
        
        if status_api == STATUS_SUCCESS {
            println!("✅ Windows API成功!");
            println!("   📄 ページサイズ: {} bytes", system_info_api.page_size);
            println!("   🧮 プロセッサ数: {}", system_info_api.number_of_processors);
            println!("   💾 物理ページ数: {}", system_info_api.number_of_physical_pages);
        } else {
            println!("❌ Windows API失敗: 0x{:08X}", status_api);
        }
        
        // 結果比較
        if status == STATUS_SUCCESS && status_api == STATUS_SUCCESS {
            let pages_match = system_info.page_size == system_info_api.page_size;
            let processors_match = system_info.number_of_processors == system_info_api.number_of_processors;
            
            println!("\n🔍 結果比較:");
            println!("   ページサイズ一致: {}", if pages_match { "✅" } else { "❌" });
            println!("   プロセッサ数一致: {}", if processors_match { "✅" } else { "❌" });
            
            if pages_match && processors_match {
                println!("🎉 Direct SyscallとWindows APIの結果が完全一致!");
            }
        }
    }
    
    Ok(())
}

fn test_process_information() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 プロセス基本情報テスト");
    println!("------------------------");
    
    unsafe {
        let current_process = GetCurrentProcess();
        let mut process_info: PROCESS_BASIC_INFORMATION = mem::zeroed();
        let mut return_length: u32 = 0;
        
        // Direct Syscall版
        println!("🔧 Direct Syscall実行中...");
        let status = direct_syscall::nt_query_information_process_direct(
            current_process,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut process_info as *mut _ as *mut c_void,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
        
        if status == STATUS_SUCCESS {
            println!("✅ Direct Syscall成功!");
            println!("   🆔 プロセスID: {}", process_info.unique_process_id);
            println!("   👑 基本優先度: {}", process_info.base_priority);
            println!("   🏁 終了状態: {}", process_info.exit_status);
        } else {
            println!("❌ Direct Syscall失敗: 0x{:08X}", status);
        }
        
        // Windows API版（比較用）
        let mut process_info_api: PROCESS_BASIC_INFORMATION = mem::zeroed();
        let mut return_length_api: u32 = 0;
        
        println!("🔧 Windows API実行中...");
        let status_api = NtQueryInformationProcess(
            current_process,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut process_info_api as *mut _ as *mut c_void,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length_api,
        );
        
        if status_api == STATUS_SUCCESS {
            println!("✅ Windows API成功!");
            println!("   🆔 プロセスID: {}", process_info_api.unique_process_id);
            println!("   👑 基本優先度: {}", process_info_api.base_priority);
            println!("   🏁 終了状態: {}", process_info_api.exit_status);
        } else {
            println!("❌ Windows API失敗: 0x{:08X}", status_api);
        }
        
        // 結果比較
        if status == STATUS_SUCCESS && status_api == STATUS_SUCCESS {
            let pid_match = process_info.unique_process_id == process_info_api.unique_process_id;
            let priority_match = process_info.base_priority == process_info_api.base_priority;
            
            println!("\n🔍 結果比較:");
            println!("   プロセスID一致: {}", if pid_match { "✅" } else { "❌" });
            println!("   基本優先度一致: {}", if priority_match { "✅" } else { "❌" });
            
            if pid_match && priority_match {
                println!("🎉 Direct SyscallとWindows APIの結果が完全一致!");
            }
        }
    }
    
    Ok(())
}

fn benchmark_performance() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚡ パフォーマンスベンチマーク");
    println!("===========================");
    
    const ITERATIONS: u32 = 10000;
    println!("実行回数: {} 回", ITERATIONS);
    
    unsafe {
        let mut system_info: SYSTEM_BASIC_INFORMATION = mem::zeroed();
        let mut return_length: u32 = 0;
        
        // Direct Syscall ベンチマーク
        println!("\n🚀 Direct Syscall ベンチマーク実行中...");
        let start_direct = std::time::Instant::now();
        
        for _ in 0..ITERATIONS {
            let _ = direct_syscall::nt_query_system_information_direct(
                SYSTEM_BASIC_INFORMATION_CLASS,
                &mut system_info as *mut _ as *mut c_void,
                mem::size_of::<SYSTEM_BASIC_INFORMATION>() as u32,
                &mut return_length,
            );
        }
        
        let direct_duration = start_direct.elapsed();
        
        // Windows API ベンチマーク
        println!("🔧 Windows API ベンチマーク実行中...");
        let start_api = std::time::Instant::now();
        
        for _ in 0..ITERATIONS {
            let _ = NtQuerySystemInformation(
                SYSTEM_BASIC_INFORMATION_CLASS,
                &mut system_info as *mut _ as *mut c_void,
                mem::size_of::<SYSTEM_BASIC_INFORMATION>() as u32,
                &mut return_length,
            );
        }
        
        let api_duration = start_api.elapsed();
        
        // 結果表示
        println!("\n📈 ベンチマーク結果:");
        println!("   Direct Syscall: {:.2}ms ({:.0}ns/call)", 
                 direct_duration.as_secs_f64() * 1000.0,
                 direct_duration.as_nanos() as f64 / ITERATIONS as f64);
        println!("   Windows API:    {:.2}ms ({:.0}ns/call)", 
                 api_duration.as_secs_f64() * 1000.0,
                 api_duration.as_nanos() as f64 / ITERATIONS as f64);
        
        // パフォーマンス向上計算
        if api_duration.as_nanos() > 0 {
            let improvement = (api_duration.as_nanos() as f64 - direct_duration.as_nanos() as f64) 
                            / api_duration.as_nanos() as f64 * 100.0;
            
            if improvement > 0.0 {
                println!("   🎯 パフォーマンス向上: {:.1}% 高速化", improvement);
            } else {
                println!("   ⚠️  パフォーマンス低下: {:.1}% 低速化", improvement.abs());
            }
        }
        
        // 1回あたりの平均時間
        let direct_avg = direct_duration.as_nanos() as f64 / ITERATIONS as f64;
        let api_avg = api_duration.as_nanos() as f64 / ITERATIONS as f64;
        
        println!("\n⏱️  平均実行時間（1回あたり）:");
        println!("   Direct Syscall: {:.0} nanoseconds", direct_avg);
        println!("   Windows API:    {:.0} nanoseconds", api_avg);
        
        if direct_avg < api_avg {
            println!("   🏆 Direct Syscallの方が {:.0}ns 高速!", api_avg - direct_avg);
        } else {
            println!("   📊 Windows APIの方が {:.0}ns 高速", direct_avg - api_avg);
        }
    }
    
    Ok(())
}

// 非Windows環境用
#[cfg(not(target_os = "windows"))]
fn main() {
    println!("❌ このプログラムはWindows専用です");
    std::process::exit(1);
}
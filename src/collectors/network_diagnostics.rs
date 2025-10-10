use std::process::Command;

/// Collects non-sensitive network diagnostics metadata for debugging purposes.
/// This function intentionally avoids collecting secrets such as passwords/keys.
pub fn collect_network_diagnostics() -> Vec<String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        let mut out = Vec::new();

        // Current Wi-Fi interface status (SSID, BSSID, signal, radio type, etc.)
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "chcp 65001 >nul 2>&1 && netsh wlan show interfaces"])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("=== Wi-Fi Interfaces ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(text.lines().map(|s| s.to_string()));
            } else {
                out.push("[WARN] netsh wlan show interfaces failed".to_string());
            }
        } else {
            out.push("[WARN] netsh not available".to_string());
        }

        if let Ok(output) = Command::new("cmd")
            .args(["/C", "chcp 65001 >nul 2>&1 && netsh wlan show profiles"])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== Known Wi-Fi Profiles (Names Only) ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if line.contains("All User Profile") {
                        if let Some(name) = line.split(':').nth(1) {
                            let name = name.trim();
                            if !name.is_empty() {
                                out.push(format!("Profile: {}", name));
                            }
                        }
                    }
                }
            } else {
                out.push("[WARN] netsh wlan show profiles failed".to_string());
            }
        } else {
            out.push("[WARN] netsh not available".to_string());
        }

        // Visible Wi-Fi networks (SSID and signal quality; no keys)
        if let Ok(output) = Command::new("cmd")
            .args([
                "/C",
                "chcp 65001 >nul 2>&1 && netsh wlan show networks mode=Bssid",
            ])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== Visible Wi-Fi Networks (SSID/BSSID/Signal) ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(text.lines().map(|s| s.to_string()));
            } else {
                out.push("[WARN] netsh wlan show networks failed".to_string());
            }
        } else {
            out.push("[WARN] netsh not available".to_string());
        }

        // Network adapters via WMI (name, type, MAC, status)
        if let Ok(output) = Command::new("cmd")
            .args([
                "/C",
                "chcp 65001 >nul 2>&1 && wmic path win32_networkadapter get Name,AdapterType,MACAddress,NetConnectionStatus /format:list",
            ])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== Network Adapters (WMI) ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(
                    text.lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|s| s.to_string()),
                );
            } else {
                out.push("[WARN] wmic networkadapter query failed".to_string());
            }
        } else {
            out.push("[WARN] wmic not available".to_string());
        }

        // IP configuration summary
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "chcp 65001 >nul 2>&1 && ipconfig /all"])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== IP Configuration (/all) [first 120 lines] ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(text.lines().take(120).map(|s| s.to_string()));
            } else {
                out.push("[WARN] ipconfig /all failed".to_string());
            }
        } else {
            out.push("[WARN] ipconfig not available".to_string());
        }

        // Routing table
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "chcp 65001 >nul 2>&1 && route print"])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== Route Print [first 80 lines] ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(text.lines().take(80).map(|s| s.to_string()));
            } else {
                out.push("[WARN] route print failed".to_string());
            }
        } else {
            out.push("[WARN] route not available".to_string());
        }

        // DNS cache (sample only; non-sensitive)
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "chcp 65001 >nul 2>&1 && ipconfig /displaydns"])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== DNS Cache [first 80 lines] ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(
                    text.lines()
                        .take(80)
                        .filter(|l| !l.trim().is_empty())
                        .map(|s| s.to_string()),
                );
            } else {
                out.push("[WARN] ipconfig /displaydns failed".to_string());
            }
        } else {
            out.push("[WARN] ipconfig not available".to_string());
        }

        // Proxy settings (do not include credentials)
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "chcp 65001 >nul 2>&1 && netsh winhttp show proxy"])
            .creation_flags(0x08000000)
            .stdin(std::process::Stdio::null())
            .output()
        {
            out.push("\n=== WinHTTP Proxy Settings ===".to_string());
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(text.lines().map(|s| s.to_string()));
            } else {
                out.push("[WARN] netsh winhttp show proxy failed".to_string());
            }
        } else {
            out.push("[WARN] netsh not available".to_string());
        }

        out
    }
    #[cfg(not(windows))]
    {
        // Cross-platform minimal diagnostics without secrets
        let mut out = Vec::new();

        // Network interfaces summary
        if let Ok(output) = Command::new("ip").args(["addr"]).output() {
            out.push("=== Network Interfaces (ip addr) [first 120 lines] ===".to_string());
            let text = String::from_utf8_lossy(&output.stdout);
            out.extend(text.lines().take(120).map(|s| s.to_string()));
        }

        // Routes
        if let Ok(output) = Command::new("ip").args(["route"]).output() {
            out.push("\n=== Routes (ip route) ===".to_string());
            let text = String::from_utf8_lossy(&output.stdout);
            out.extend(text.lines().map(|s| s.to_string()));
        }

        // DNS (resolv.conf)
        if let Ok(output) = Command::new("cat").args(["/etc/resolv.conf"]).output() {
            out.push("\n=== DNS (/etc/resolv.conf) ===".to_string());
            let text = String::from_utf8_lossy(&output.stdout);
            out.extend(text.lines().map(|s| s.to_string()));
        }

        out
    }
}

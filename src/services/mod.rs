// Services module - C2 (Command and Control) 機能
pub mod c2;

#[cfg(windows)]
pub mod browser_injection;

pub use c2::*;
#[cfg(windows)]
pub use browser_injection::*;
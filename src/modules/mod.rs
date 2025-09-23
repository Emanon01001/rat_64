// src/modules/mod.rs - モジュール定義ファイル

#[cfg(feature = "webhook")]
pub mod notification_sender;

#[cfg(feature = "screenshot")]
pub mod screen_capture;

// 基本システムモジュール  
pub mod common_utils;

// モジュールの再エクスポート
#[cfg(feature = "webhook")]
pub use notification_sender::*;

#[cfg(feature = "screenshot")]
pub use screen_capture::*;

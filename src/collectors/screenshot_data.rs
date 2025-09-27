// スクリーンショットデータ構造体
use serde::{Serialize, Deserialize};
// screen_captureのインポートは必要時に関数内で行う

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScreenshotData {
    pub primary_display: Option<String>,      // Base64エンコードされたプライマリディスプレイ
    pub all_displays: Vec<String>,            // Base64エンコードされた全ディスプレイ
    pub capture_time: String,                 // キャプチャ時刻
    pub total_count: usize,                   // 取得したスクリーンショット数
}

impl Default for ScreenshotData {
    fn default() -> Self {
        Self {
            primary_display: None,
            all_displays: Vec::new(),
            capture_time: format!("{:?}", std::time::SystemTime::now()),
            total_count: 0,
        }
    }
}

// スクリーンショット収集統合関数
#[cfg(feature = "screenshot")]
pub fn collect_screenshots(config: &crate::Config) -> ScreenshotData {
    if !config.collect_screenshots {
        return ScreenshotData::default();
    }
    
    use crate::utils::screen_capture::{capture_all_displays, ScreenshotConfig};
    
    match capture_all_displays(&ScreenshotConfig::default()) {
        Ok(screenshot_data) => {
            let total_count = screenshot_data.len();
            ScreenshotData {
                primary_display: screenshot_data.first().cloned(),
                all_displays: screenshot_data,
                capture_time: format!("{:?}", std::time::SystemTime::now()),
                total_count,
            }
        },
        Err(_) => ScreenshotData::default(),
    }
}

#[cfg(not(feature = "screenshot"))]
pub fn collect_screenshots(_config: &crate::Config) -> ScreenshotData {
    ScreenshotData::default()
}
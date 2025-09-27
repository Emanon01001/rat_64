// スクリーンショット機能モジュール
use base64::{engine::general_purpose, Engine as _};

#[cfg(feature = "screenshot")]
use scrap::{Capturer, Display};
#[cfg(feature = "screenshot")]
use image::{ImageBuffer, RgbaImage};

pub struct ScreenshotConfig {
    pub quality: u8,
    pub max_width: u32,
    pub max_height: u32,
}

impl Default for ScreenshotConfig {
    fn default() -> Self {
        ScreenshotConfig {
            quality: 80,
            max_width: 1920,
            max_height: 1080,
        }
    }
}

/// プライマリディスプレイのスクリーンショットを取得してBase64で返す
#[cfg(feature = "screenshot")]
pub fn capture_screenshot(config: &ScreenshotConfig) -> Result<String, Box<dyn std::error::Error>> {
    let display = Display::primary()?;
    let mut capturer = Capturer::new(display)?;
    
    let (width, height) = (capturer.width(), capturer.height());
    
    // スクリーンショットを複数回試行
    let mut attempts = 0;
    let max_attempts = 5;
    
    loop {
        attempts += 1;
        
        match capturer.frame() {
            Ok(buffer) => {
                
                // BGRAからRGBAに変換
                let mut rgba_buffer = Vec::with_capacity(buffer.len());
                for pixel in buffer.chunks_exact(4) {
                    rgba_buffer.push(pixel[2]); // R
                    rgba_buffer.push(pixel[1]); // G
                    rgba_buffer.push(pixel[0]); // B
                    rgba_buffer.push(pixel[3]); // A
                }
                
                // ImageBufferを作成
                let img: RgbaImage = ImageBuffer::from_raw(width as u32, height as u32, rgba_buffer)
                    .ok_or("画像バッファの作成に失敗")?;
                
                // リサイズ（必要に応じて）
                let (final_width, final_height) = calculate_resize_dimensions(
                    width as u32, height as u32, 
                    config.max_width, config.max_height
                );
                
                let final_img = if final_width != width as u32 || final_height != height as u32 {
                    image::imageops::resize(&img, final_width, final_height, image::imageops::FilterType::Lanczos3)
                } else {
                    img
                };
                
                // PNGとしてエンコード
                let mut png_data = Vec::new();
                final_img.write_to(&mut std::io::Cursor::new(&mut png_data), image::ImageFormat::Png)?;
                
                // Base64エンコード
                let base64_data = general_purpose::STANDARD.encode(&png_data);
                
                return Ok(base64_data);
            }
            Err(error) => {
                if attempts >= max_attempts {
                    return Err(format!("スクリーンショット取得に失敗: {}", error).into());
                }
                
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

#[cfg(not(feature = "screenshot"))]
pub fn capture_screenshot(_config: &ScreenshotConfig) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::new())
}

/// 複数のディスプレイのスクリーンショットを取得
#[cfg(feature = "screenshot")]
pub fn capture_all_displays(config: &ScreenshotConfig) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let displays = Display::all()?;
    let mut screenshots = Vec::new();
    
    for display in displays.into_iter() {
        if let Ok(screenshot) = capture_display_screenshot(display, config) {
            screenshots.push(screenshot);
        }
    }
    
    Ok(screenshots)
}

#[cfg(feature = "screenshot")]
fn capture_display_screenshot(display: Display, config: &ScreenshotConfig) -> Result<String, Box<dyn std::error::Error>> {
    let mut capturer = Capturer::new(display)?;
    let (width, height) = (capturer.width(), capturer.height());
    
    // 複数回試行
    for _ in 0..3 {
        match capturer.frame() {
            Ok(buffer) => {
                // BGRA to RGBA conversion
                let mut rgba_buffer = Vec::with_capacity(buffer.len());
                for pixel in buffer.chunks_exact(4) {
                    rgba_buffer.push(pixel[2]); // R
                    rgba_buffer.push(pixel[1]); // G  
                    rgba_buffer.push(pixel[0]); // B
                    rgba_buffer.push(pixel[3]); // A
                }
                
                let img: RgbaImage = ImageBuffer::from_raw(width as u32, height as u32, rgba_buffer)
                    .ok_or("画像バッファの作成に失敗")?;
                
                // リサイズ
                let (final_width, final_height) = calculate_resize_dimensions(
                    width as u32, height as u32,
                    config.max_width, config.max_height
                );
                
                let final_img = if final_width != width as u32 || final_height != height as u32 {
                    image::imageops::resize(&img, final_width, final_height, image::imageops::FilterType::Lanczos3)
                } else {
                    img
                };
                
                // PNG エンコード
                let mut png_data = Vec::new();
                final_img.write_to(&mut std::io::Cursor::new(&mut png_data), image::ImageFormat::Png)?;
                
                return Ok(general_purpose::STANDARD.encode(&png_data));
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    
    Err("ディスプレイキャプチャに失敗".into())
}

fn calculate_resize_dimensions(original_width: u32, original_height: u32, max_width: u32, max_height: u32) -> (u32, u32) {
    if original_width <= max_width && original_height <= max_height {
        return (original_width, original_height);
    }
    
    let width_ratio = max_width as f64 / original_width as f64;
    let height_ratio = max_height as f64 / original_height as f64;
    let scale_ratio = width_ratio.min(height_ratio);
    
    let new_width = (original_width as f64 * scale_ratio) as u32;
    let new_height = (original_height as f64 * scale_ratio) as u32;
    
    (new_width, new_height)
}

/// スクリーンショットを指定されたパスに保存
pub fn save_screenshot_to_file(base64_data: &str, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if base64_data.is_empty() {
        return Err("スクリーンショットデータが空です".into());
    }
    
    let image_data = general_purpose::STANDARD.decode(base64_data)?;
    std::fs::write(file_path, image_data)?;
    
    Ok(())
}

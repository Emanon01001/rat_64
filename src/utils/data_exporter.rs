use anyhow::Result;
use serde_json::Value;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

pub trait OutputFormat {
    fn output(&self) -> Result<()>;
}

pub struct HumanOutput {
    items: Vec<Value>,
}

impl HumanOutput {
    pub fn new(items: Vec<Value>) -> Self {
        Self { items }
    }
}

impl OutputFormat for HumanOutput {
    fn output(&self) -> Result<()> {
        for v in &self.items {
            let url = v["url"].as_str().unwrap_or("<no url>");
            let user = v["user"].as_str().unwrap_or("<no user>");
            let pass = v["password"].as_str().unwrap_or("<no pass>");
            writeln!(
                io::stdout(),
                "Website: {}\nUsername: '{}'\nPassword: '{}'\n",
                url,
                user,
                pass
            )?;
        }
        Ok(())
    }
}

pub struct JsonOutput {
    items: Vec<Value>,
}

impl JsonOutput {
    pub fn new(items: Vec<Value>) -> Self {
        Self { items }
    }
}

impl OutputFormat for JsonOutput {
    fn output(&self) -> Result<()> {
        let json_str = serde_json::to_string_pretty(&self.items)?;
        writeln!(io::stdout(), "{}", json_str)?;
        Ok(())
    }
}

pub struct CsvOutput {
    items: Vec<Value>,
}

impl CsvOutput {
    pub fn new(items: Vec<Value>) -> Self {
        Self { items }
    }
}

impl OutputFormat for CsvOutput {
    fn output(&self) -> Result<()> {
        // CSV機能を標準ライブラリで実装
        writeln!(io::stdout(), "url,username,password")?;
        for v in &self.items {
            let url = v["url"].as_str().unwrap_or("").replace(",", ";");
            let user = v["user"].as_str().unwrap_or("").replace(",", ";");
            let password = v["password"].as_str().unwrap_or("").replace(",", ";");
            writeln!(io::stdout(), "{},{},{}", url, user, password)?;
        }
        Ok(())
    }
}

/// ファイルに出力する統合エクスポーター
pub struct FileExporter {
    items: Vec<Value>,
}

impl FileExporter {
    pub fn new(items: Vec<Value>) -> Self {
        Self { items }
    }

    /// JSONファイルとして出力
    pub fn export_json<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        let json_str = serde_json::to_string_pretty(&self.items)?;
        fs::write(file_path, json_str)?;
        Ok(())
    }

    /// CSVファイルとして出力
    pub fn export_csv<P: AsRef<Path>>(&self, file_path: P) -> Result<()> {
        let mut output = String::new();
        output.push_str("url,username,password\n");

        for v in &self.items {
            let url = v["url"].as_str().unwrap_or("").replace(",", ";");
            let user = v["user"].as_str().unwrap_or("").replace(",", ";");
            let password = v["password"].as_str().unwrap_or("").replace(",", ";");
            output.push_str(&format!("{},{},{}\n", url, user, password));
        }

        fs::write(file_path, output)?;
        Ok(())
    }

    /// ファイルをエクスポートして、オプションでアップロード
    #[cfg(feature = "network")]
    pub fn export_and_upload_json<P: AsRef<Path>>(
        &self,
        file_path: P,
        uploader: Option<&crate::network::file_uploader::Uploader>,
    ) -> Result<Option<crate::network::file_uploader::UploadResult>> {
        // まずファイルをエクスポート
        self.export_json(&file_path)?;

        // アップローダーがあればアップロード実行
        if let Some(uploader) = uploader {
            let result = uploader
                .upload(&file_path)
                .map_err(|e| anyhow::anyhow!("Upload failed: {}", e))?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// network機能が無効な場合のスタブ
    #[cfg(not(feature = "network"))]
    pub fn export_and_upload_json<P: AsRef<Path>>(
        &self,
        file_path: P,
        _upload_config: Option<&()>,
    ) -> Result<Option<()>> {
        // ファイルエクスポートのみ実行
        self.export_json(file_path)?;
        Ok(None)
    }
}

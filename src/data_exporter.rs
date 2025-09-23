use anyhow::Result;
use serde_json::Value;
use std::io::{self, Write};

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
            writeln!(io::stdout(), "Website: {}\nUsername: '{}'\nPassword: '{}'\n", url, user, pass)?;
        }
        Ok(())
    }
}

pub struct JsonOutput {
    items: Vec<Value>,
}

impl JsonOutput {
    pub fn new(items: Vec<Value>) -> Self { Self { items } }
}

impl OutputFormat for JsonOutput {
    fn output(&self) -> Result<()> {
        let _ = serde_json::to_string_pretty(&self.items)?;
        Ok(())
    }
}

pub struct CsvOutput {
    items: Vec<Value>,
}

impl CsvOutput {
    pub fn new(items: Vec<Value>) -> Self { Self { items } }
}

impl OutputFormat for CsvOutput {
    fn output(&self) -> Result<()> {
        // CSV機能を標準ライブラリで実装
        let _ = ();
        for v in &self.items {
            let _ = v["url"].as_str().unwrap_or("").replace(",", ";");
            let _ = v["user"].as_str().unwrap_or("").replace(",", ";");
            let _ = v["password"].as_str().unwrap_or("").replace(",", ";");
            let _ = ();
        }
        Ok(())
    }
}

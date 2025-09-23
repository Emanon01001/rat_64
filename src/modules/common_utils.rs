// 共通ユーティリティ関数
use std::collections::HashMap;

/// プログレスバーと状態表示の統一化
pub struct ProgressReporter {
    _module_name: String,
}

impl ProgressReporter {
    pub fn new(module_name: &str) -> Self {
        Self {
            _module_name: module_name.to_string(),
        }
    }

    pub fn start(&self, _task: &str) {
        // サイレント実行
    }

    pub fn step(&self, _step: &str, _count: usize) {
        // サイレント実行
    }

    pub fn complete(&self, _summary: &str) {
        // サイレント実行
    }

    pub fn error(&self, _error: &str) {
        // サイレント実行
    }
}

/// 共通のエラーハンドリング
pub fn safe_collect<F, T>(_name: &str, collector: F) -> Vec<T>
where
    F: FnOnce() -> Result<Vec<T>, Box<dyn std::error::Error>>,
{
    match collector() {
        Ok(items) => {
            items
        }
        Err(_) => {
            Vec::new()
        }
    }
}

/// 共通のコマンド実行ヘルパー
#[cfg(windows)]
pub fn execute_windows_command(command: &str, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(command)
        .args(args)
        .output()?;
    
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("Command failed: {}", String::from_utf8_lossy(&output.stderr)).into())
    }
}

/// 共通のタイマー実装
pub struct Timer {
    start: std::time::Instant,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    pub fn elapsed_seconds(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

/// 共通のデータ形式変換
pub fn format_count_summary(counts: HashMap<&str, usize>) -> String {
    counts
        .iter()
        .map(|(name, count)| format!("{}: {}件", name, count))
        .collect::<Vec<_>>()
        .join(", ")
}

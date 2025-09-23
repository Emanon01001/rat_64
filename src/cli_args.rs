// 簡素なCLI実装（標準ライブラリ版）
use std::path::PathBuf;
use std::env;

/// 簡素化されたCLI引数構造体
#[derive(Debug, Default)]
pub struct Args {
    pub profile: Option<PathBuf>,
    pub format: String,
    pub verbose: i32,
    pub non_fatal_decryption: bool,
    pub choice: bool,
    pub list: bool,
    pub no_interactive: bool,
}

impl Args {
    /// 標準ライブラリでCLI引数を解析
    pub fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut parsed_args = Args {
            format: "human".to_string(),
            ..Default::default()
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-v" | "--verbose" => parsed_args.verbose += 1,
                "-f" | "--format" => {
                    if i + 1 < args.len() {
                        parsed_args.format = args[i + 1].clone();
                        i += 1;
                    }
                }
                "--non-fatal-decryption" => parsed_args.non_fatal_decryption = true,
                "-c" | "--choice" => parsed_args.choice = true,
                "-l" | "--list" => parsed_args.list = true,
                "-n" | "--no-interactive" => parsed_args.no_interactive = true,
                _ => {
                    // 最初の位置引数をプロファイルとして扱う
                    if !args[i].starts_with("-") && parsed_args.profile.is_none() {
                        parsed_args.profile = Some(PathBuf::from(&args[i]));
                    }
                }
            }
            i += 1;
        }

        parsed_args
    }
}

/// デフォルトプロファイルパスを取得
pub fn get_default_profile_path() -> PathBuf {
    // Windowsのデフォルトパス
    if let Ok(appdata) = env::var("APPDATA") {
        return PathBuf::from(appdata).join("Mozilla").join("Firefox");
    }
    
    // Linuxのデフォルトパス
    if let Ok(home) = env::var("HOME") {
        let firefox_path = PathBuf::from(home).join(".mozilla").join("firefox");
        if firefox_path.exists() {
            return firefox_path;
        }
    }

    // フォールバック
    PathBuf::from(".")
}

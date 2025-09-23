use clap::Parser;
use std::path::PathBuf;

/// Firefox/Thunderbird パスワード復号化ツール - Python版の完全な移植
#[derive(Parser, Debug)]
#[command(
    name = "firefox_decrypt_rs", 
    author, 
    version, 
    about = "Access Firefox/Thunderbird profiles and decrypt existing passwords"
)]
pub struct Args {
    /// Path to profile folder (default: platform-specific Firefox profile location)
    #[arg(value_name = "PROFILE")]
    pub profile: Option<PathBuf>,

    /// Format for the output
    #[arg(short = 'f', long, default_value = "human")]
    pub format: String,

    /// The delimiter for csv output
    #[arg(short = 'd', long = "csv-delimiter", default_value = ";")]
    pub csv_delimiter: String,

    /// The quote char for csv output  
    #[arg(short = 'q', long = "csv-quotechar", default_value = "\"")]
    pub csv_quotechar: String,

    /// Do not include a header in CSV output
    #[arg(long = "no-csv-header")]
    pub no_csv_header: bool,

    /// Export username as is (default), or with the provided format prefix
    #[arg(long = "pass-username-prefix", default_value = "")]
    pub pass_username_prefix: String,

    /// Folder prefix for export to pass from passwordstore.org
    #[arg(short = 'p', long = "pass-prefix", default_value = "web")]
    pub pass_prefix: String,

    /// Command/path to use when exporting to pass
    #[arg(short = 'm', long = "pass-cmd", default_value = "pass")]
    pub pass_cmd: String,

    /// Always save as /<login> (default: only when multiple accounts per domain)
    #[arg(long = "pass-always-with-login")]
    pub pass_always_with_login: bool,

    /// Disable interactivity
    #[arg(short = 'n', long = "no-interactive")]
    pub no_interactive: bool,

    /// If set, corrupted entries will be skipped instead of aborting the process
    #[arg(long = "non-fatal-decryption")]
    pub non_fatal_decryption: bool,

    /// The profile to use (starts with 1). If only one profile, defaults to that
    #[arg(short = 'c', long = "choice")]
    pub choice: Option<String>,

    /// List profiles and exit
    #[arg(short = 'l', long = "list")]
    pub list: bool,

    /// Override default encoding
    #[arg(short = 'e', long = "encoding", default_value = "utf-8")]
    pub encoding: String,

    /// Verbosity level. Can be used multiple times (-v, -vv)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

pub fn parse_args() -> Args {
    let mut args = Args::parse();
    
    // Handle tab character in CSV delimiter like Python version
    if args.csv_delimiter == "\\t" {
        args.csv_delimiter = "\t".to_string();
    }
    
    args
}

/// Get default profile path based on platform
pub fn get_default_profile_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| "C:".to_string());
        PathBuf::from(appdata).join("Mozilla").join("Firefox")
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/"))
            .join("Library")
            .join("Application Support")
            .join("Firefox")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/"))
            .join(".mozilla")
            .join("firefox")
    }
}

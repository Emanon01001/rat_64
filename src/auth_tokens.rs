// 簡素化されたauth_tokensモジュール
// 実際のDiscordトークン抽出機能はlib.rsのextract_discord_tokens_advanced()に統合されています

#[derive(Debug)]
pub enum TokenError {
    DpapiError { message: String },
    FileReadError { path: String },
    JsonParseError(serde_json::Error),
    Base64DecodeError(base64::DecodeError),
    EncryptedKeyNotFound,
    InvalidKeyFormat,
    AesDecryptionError(String),
    InvalidDataFormat { length: usize },
    NoTokensFound,
    AllDecryptionsFailed,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::DpapiError { message } => write!(f, "DPAPI復号に失敗しました: {}", message),
            TokenError::FileReadError { path } => write!(f, "ファイル読み込みエラー: {}", path),
            TokenError::JsonParseError(err) => write!(f, "JSON解析エラー: {}", err),
            TokenError::Base64DecodeError(err) => write!(f, "Base64デコードエラー: {}", err),
            TokenError::EncryptedKeyNotFound => write!(f, "暗号化キーが見つかりません"),
            TokenError::InvalidKeyFormat => write!(f, "キーのDPAPIプレフィックスが見つかりません"),
            TokenError::AesDecryptionError(msg) => write!(f, "AES復号化エラー: {}", msg),
            TokenError::InvalidDataFormat { length } => write!(f, "データフォーマットが無効です (長さ: {})", length),
            TokenError::NoTokensFound => write!(f, "暗号化トークンが見つかりませんでした"),
            TokenError::AllDecryptionsFailed => write!(f, "すべてのトークンの復号に失敗しました"),
        }
    }
}

impl std::error::Error for TokenError {}

impl From<serde_json::Error> for TokenError {
    fn from(err: serde_json::Error) -> Self {
        TokenError::JsonParseError(err)
    }
}

impl From<base64::DecodeError> for TokenError {
    fn from(err: base64::DecodeError) -> Self {
        TokenError::Base64DecodeError(err)
    }
}

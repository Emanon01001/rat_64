use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;
use std::fs;

#[cfg(feature = "browser")]
use rusqlite;

use crate::firefox_nss::Nss;

pub trait CredentialsBackend {
    /// returns iterator over tuples: (hostname, encryptedUsername, encryptedPassword, encType)
    fn iter(&self) -> Result<Vec<(String, String, String, i32)>>;
}

/// Decrypted login information
#[derive(Debug, Clone)]
pub struct DecryptedLogin {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub enc_type: i32,
}

/// NSS-enabled credentials backend that can decrypt passwords
pub struct NssCredentials {
    profile_path: PathBuf,
}

impl NssCredentials {
    pub fn new(profile_path: PathBuf) -> Self {
        Self { profile_path }
    }
    
    /// Get decrypted logins from the Firefox profile
    pub fn get_decrypted_logins(&self) -> Result<Vec<DecryptedLogin>> {
        let mut decrypted_logins = Vec::new();
        
        // Initialize NSS
        let nss = Nss::new()?;
        nss.initialize(&self.profile_path)?;
        
        // Try JSON credentials first
        let json_path = self.profile_path.join("logins.json");
        if json_path.exists() {
            if let Ok(json_creds) = JsonCredentials::open(json_path) {
                if let Ok(logins) = json_creds.iter() {
                    for (hostname, encrypted_username, encrypted_password, enc_type) in logins {
                        let username = if encrypted_username.is_empty() {
                            String::new()
                        } else {
                            nss.decrypt(&encrypted_username).unwrap_or_else(|_| encrypted_username)
                        };
                        
                        let password = if encrypted_password.is_empty() {
                            String::new()
                        } else {
                            nss.decrypt(&encrypted_password).unwrap_or_else(|_| "[DECRYPT_FAILED]".to_string())
                        };
                        
                        decrypted_logins.push(DecryptedLogin {
                            hostname,
                            username,
                            password,
                            enc_type,
                        });
                    }
                }
            }
        }
        
        // Try SQLite credentials if browser feature is enabled
        #[cfg(feature = "browser")]
        {
            let sqlite_path = self.profile_path.join("signons.sqlite");
            if sqlite_path.exists() {
                if let Ok(sqlite_creds) = SqliteCredentials::open(sqlite_path) {
                    if let Ok(logins) = sqlite_creds.iter() {
                        for (hostname, encrypted_username, encrypted_password, enc_type) in logins {
                            let username = if encrypted_username.is_empty() {
                                String::new()
                            } else {
                                nss.decrypt(&encrypted_username).unwrap_or_else(|_| encrypted_username)
                            };
                            
                            let password = if encrypted_password.is_empty() {
                                String::new()
                            } else {
                                nss.decrypt(&encrypted_password).unwrap_or_else(|_| "[DECRYPT_FAILED]".to_string())
                            };
                            
                            decrypted_logins.push(DecryptedLogin {
                                hostname,
                                username,
                                password,
                                enc_type,
                            });
                        }
                    }
                }
            }
        }
        
        // Shutdown NSS
        let _ = nss.shutdown();
        
        Ok(decrypted_logins)
    }
}

/// JSON backend (logins.json)
pub struct JsonCredentials {
    path: PathBuf,
}

impl JsonCredentials {
    pub fn open(path: PathBuf) -> Result<Self> {
        Ok(JsonCredentials { path })
    }
}

#[derive(Deserialize)]
struct LoginEntry {
    hostname: String,
    #[serde(rename = "encryptedUsername")]
    encrypted_username: String,
    #[serde(rename = "encryptedPassword")]
    encrypted_password: String,
    #[serde(rename = "encType", default)]
    enc_type: i32,
}

#[derive(Deserialize)]
struct LoginsFile {
    logins: Vec<LoginEntry>,
}

impl CredentialsBackend for JsonCredentials {
    fn iter(&self) -> Result<Vec<(String, String, String, i32)>> {
        let data = fs::read_to_string(&self.path)?;
        let parsed: LoginsFile = serde_json::from_str(&data)?;
        Ok(parsed
            .logins
            .into_iter()
            .map(|e| (e.hostname, e.encrypted_username, e.encrypted_password, e.enc_type))
            .collect())
    }
}

/// SQLite backend (signons.sqlite) - stubbed minimal implementation
pub struct SqliteCredentials {
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl SqliteCredentials {
    pub fn open(db_path: PathBuf) -> Result<Self> {
        // TODO: implement rusqlite usage (make rusqlite an optional dependency)
        Ok(SqliteCredentials { db_path })
    }
}

impl CredentialsBackend for SqliteCredentials {
    fn iter(&self) -> Result<Vec<(String, String, String, i32)>> {
        #[cfg(feature = "browser")]
        {
            if !self.db_path.exists() {
                anyhow::bail!("SQLite database not found: {}", self.db_path.display());
            }

            let conn = rusqlite::Connection::open(&self.db_path)?;
            
            let mut stmt = conn.prepare(
                "SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins"
            )?;

            let mut results = Vec::new();
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,  // hostname
                    row.get::<_, String>(1)?,  // encryptedUsername  
                    row.get::<_, String>(2)?,  // encryptedPassword
                    row.get::<_, i32>(3)?,     // encType
                ))
            })?;

            for row in rows {
                match row {
                    Ok(login) => results.push(login),
                    Err(_) => {}
                }
            }

            Ok(results)
        }
        
        #[cfg(not(feature = "browser"))]
        {
            anyhow::bail!("SQLite support not compiled in");
        }
    }
}

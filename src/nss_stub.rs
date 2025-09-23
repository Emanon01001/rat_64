//! NSS (Network Security Services) stub
//!
//! This module intentionally provides a no-op implementation to avoid
//! interacting with credential stores. It preserves the public API so the
//! project compiles, but returns errors for decryption-related calls.

use anyhow::{anyhow, Result};
use std::path::Path;

pub struct Nss;

impl Nss {
    /// Construct a stub NSS handle
    pub fn new() -> Result<Self> {
        Ok(Nss)
    }

    /// Initialize with a profile path (no-op)
    pub fn initialize(&self, _profile_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Attempt to "decrypt" input; always returns an error in the stub
    pub fn decrypt(&self, _b64_data: &str) -> Result<String> {
        Err(anyhow!("NSS decryption is disabled in this build"))
    }

    /// Shutdown NSS (no-op)
    pub fn shutdown(self) -> Result<()> {
        Ok(())
    }
}


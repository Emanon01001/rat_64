//! NSS (Network Security Services) FFI wrapper for Firefox password decryption
//! 
//! This module provides a safe Rust wrapper around the NSS C library functions
//! needed to decrypt Firefox/Thunderbird stored passwords.

use std::{
    env,
    ffi::{c_char, c_int, CString},  
    path::{Path, PathBuf},
    ptr,
};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use libloading::Library;
use which::which;

type CUint = std::os::raw::c_uint;

#[repr(C)]
struct SECItem {
    item_type: CUint,
    data: *mut u8,
    len: CUint,
}

// NSS constants
const SEC_SUCCESS: c_int = 0;
#[allow(dead_code)]
const SEC_FAILURE: c_int = -1;

/// Load NSS library from one of the many possible locations
pub fn load_libnss() -> Result<Library> {
    let nss_lib_path = env::var("NSS_LIB_PATH").unwrap_or_default();
    let mut locations = vec![nss_lib_path];

    // Windows-only implementation
    let nssname = "nss3.dll";
    
    // Add 32-bit locations first if not on 64-bit
    if !cfg!(target_pointer_width = "64") {
        locations.extend_from_slice(&[
            String::new(), // Current directory or system lib finder
            r"C:\Program Files (x86)\Mozilla Firefox".to_string(),
            r"C:\Program Files (x86)\Firefox Developer Edition".to_string(),
            r"C:\Program Files (x86)\Mozilla Thunderbird".to_string(),  
            r"C:\Program Files (x86)\Nightly".to_string(),
            r"C:\Program Files (x86)\SeaMonkey".to_string(),
            r"C:\Program Files (x86)\Waterfox".to_string(),
        ]);
    }

    // Add common locations
    // dirs::home_dir()を標準ライブラリで置換
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    locations.extend_from_slice(&[
        String::new(), // Current directory or system lib finder
        format!("{}\\AppData\\Local\\Mozilla Firefox", home_dir.display()),
        format!("{}\\AppData\\Local\\Firefox Developer Edition", home_dir.display()),
        format!("{}\\AppData\\Local\\Mozilla Thunderbird", home_dir.display()),
        format!("{}\\AppData\\Local\\Nightly", home_dir.display()),
        format!("{}\\AppData\\Local\\SeaMonkey", home_dir.display()),
        format!("{}\\AppData\\Local\\Waterfox", home_dir.display()),
        r"C:\Program Files\Mozilla Firefox".to_string(),
        r"C:\Program Files\Firefox Developer Edition".to_string(),
        r"C:\Program Files\Mozilla Thunderbird".to_string(),
        r"C:\Program Files\Nightly".to_string(),
        r"C:\Program Files\SeaMonkey".to_string(),
        r"C:\Program Files\Waterfox".to_string(),
    ]);

    // Check PATH for supported software
    let software = &["firefox", "thunderbird", "waterfox", "seamonkey"];
    for binary in software {
        if let Ok(location) = which(binary) {
            if let Some(parent) = location.parent() {
                let nss_location = parent.join(nssname);
                locations.push(nss_location.display().to_string());
            }
        }
    }

    find_nss(locations)
}

/// Find NSS library in one of the many possible locations (Windows only)
fn find_nss(locations: Vec<String>) -> Result<Library> {
    let nssname = "nss3.dll";

    let mut fail_errors = Vec::new();
    let original_dir = env::current_dir().ok();

    for loc in locations {
        let nsslib = if loc.is_empty() {
            nssname.to_string()
        } else {
            PathBuf::from(&loc).join(nssname).display().to_string()
        };
        
        let _ = nsslib;

        // On Windows, manage PATH and working directory
        if !loc.is_empty() {
            let loc_path = Path::new(&loc);
            if !loc_path.is_dir() {
                // No point in trying to load from paths that don't exist
                continue;
            }

            // Add location to PATH
            let current_path = env::var("PATH").unwrap_or_default();
            unsafe {
                env::set_var("PATH", format!("{};{}", loc, current_path));
            }
            let _ = env::var("PATH");

            // Change to the library directory as workaround for DLL dependencies
            if let Err(_) = env::set_current_dir(&loc) {
                continue;
            }
        }

        // Try to load the library
        let nss_result = unsafe { Library::new(&nsslib) };
        
        match nss_result {
            Ok(nss) => {
                let _ = nsslib;
                // Restore original directory
                if let Some(ref orig_dir) = original_dir {
                    let _ = env::set_current_dir(orig_dir);
                }
                return Ok(nss);
            }
            Err(e) => {
                fail_errors.push((nsslib, e.to_string()));
            }
        }

        // Restore original directory after failed attempt
        if let Some(ref orig_dir) = original_dir {
            let _ = env::set_current_dir(orig_dir);
        }
    }

    // If we get here, all attempts failed
    let _ = (nssname, &fail_errors);

    Err(anyhow!("Failed to locate NSS library"))
}

pub struct Nss {
    _lib: Library,
    nss_init: unsafe extern "C" fn(*const c_char) -> c_int,
    nss_shutdown: unsafe extern "C" fn() -> c_int,
    pk11sdr_decrypt: unsafe extern "C" fn(*const SECItem, *mut SECItem, *mut std::ffi::c_void) -> c_int,
    secitem_zfree_item: unsafe extern "C" fn(*mut SECItem, c_int),
}

impl Nss {
    /// Load NSS library and initialize function pointers using the comprehensive load_libnss function
    pub fn new() -> Result<Self> {
        let lib = load_libnss().context("Could not find NSS library. Please ensure Firefox/NSS is installed and all dependencies are available.")?;

        macro_rules! get_symbol {
            ($name:literal) => {{
                let symbol_name = concat!($name, "\0");
                unsafe { *lib.get(symbol_name.as_bytes())? }
            }};
        }

        Ok(Self {
            nss_init: get_symbol!("NSS_Init"),
            nss_shutdown: get_symbol!("NSS_Shutdown"),
            pk11sdr_decrypt: get_symbol!("PK11SDR_Decrypt"),
            secitem_zfree_item: get_symbol!("SECITEM_ZfreeItem"),
            _lib: lib,
        })
    }

    /// Initialize NSS with the given profile path
    pub fn initialize(&self, profile_path: &Path) -> Result<()> {
        // Python uses "sql:" prefix for compatibility with both Berkley DB and Sqlite
        let profile_str = format!("sql:{}", profile_path.display());
        let c_path = CString::new(profile_str.as_str())?;
        let _ = profile_str;
        
        let result = unsafe { (self.nss_init)(c_path.as_ptr()) };
        let _ = result;
        
        if result != SEC_SUCCESS {
            return Err(anyhow!("NSS initialization failed with code {}. Is '{}' a valid Firefox profile?", result, profile_path.display()));
        }
        let _ = profile_path;
        
        Ok(())
    }

    /// Decrypt base64-encoded NSS data
    pub fn decrypt_base64(&self, data: &[u8]) -> Result<Vec<u8>> {
        let input = SECItem {
            item_type: 0,
            data: data.as_ptr() as *mut u8,
            len: data.len() as CUint,
        };

        let mut output = SECItem {
            item_type: 0,
            data: ptr::null_mut(),
            len: 0,
        };

        let result = unsafe { (self.pk11sdr_decrypt)(&input, &mut output, ptr::null_mut()) };
        
        if result != SEC_SUCCESS {
            return Err(anyhow!("Decryption failed with code {}. Credentials might be damaged or cert/key file mismatch.", result));
        }

        let decrypted_data = unsafe {
            std::slice::from_raw_parts(output.data as *const u8, output.len as usize).to_vec()
        };
        
        // Free the allocated memory
        unsafe { (self.secitem_zfree_item)(&mut output, 0) };
        
        Ok(decrypted_data)
    }

    /// Convert decrypted bytes to UTF-8 string
    pub fn decrypt(&self, b64_data: &str) -> Result<String> {
        let decoded_data = b64.decode(b64_data)?;
        let bytes = self.decrypt_base64(&decoded_data)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Shutdown NSS
    pub fn shutdown(self) -> Result<()> {
        let result = unsafe { (self.nss_shutdown)() };
        if result != SEC_SUCCESS {
            return Err(anyhow!("NSS shutdown failed with code {}", result));
        }
        let _ = result;
        Ok(())
    }
}

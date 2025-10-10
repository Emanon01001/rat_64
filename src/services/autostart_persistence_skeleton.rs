use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPrefs {
    pub autostart: bool,
}

impl Default for AppPrefs {
    fn default() -> Self {
        Self { autostart: false }
    }
}

#[derive(Debug, Clone)]
pub struct OneFileApp {
    vendor: String,
    app: String,
    config_path: PathBuf,
    data_dir: PathBuf,
}

impl OneFileApp {
    pub fn new(vendor: impl Into<String>, app: impl Into<String>) -> Result<Self> {
        let vendor = vendor.into();
        let app = app.into();
        let (config_dir, data_dir) = Self::resolve_dirs(&vendor, &app)?;
        fs::create_dir_all(&config_dir).context("create config dir")?;
        fs::create_dir_all(&data_dir).context("create data dir")?;
        let config_path = config_dir.join("prefs.json");
        Ok(Self {
            vendor,
            app,
            config_path,
            data_dir,
        })
    }

    fn resolve_dirs(vendor: &str, app: &str) -> Result<(PathBuf, PathBuf)> {
        let config_base = dirs::config_dir().context("config_dir not available")?;
        let data_base = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .context("data_dir not available")?;
        Ok((
            config_base.join(vendor).join(app),
            data_base.join(vendor).join(app),
        ))
    }

    pub fn load_prefs(&self) -> Result<AppPrefs> {
        if !self.config_path.exists() {
            return Ok(AppPrefs::default());
        }
        let bytes = fs::read(&self.config_path).context("read prefs")?;
        let prefs: AppPrefs = serde_json::from_slice(&bytes).context("parse prefs")?;
        Ok(prefs)
    }

    pub fn save_prefs(&self, prefs: &AppPrefs) -> Result<()> {
        let tmp = self.config_path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(prefs).context("serialize prefs")?;
        fs::write(&tmp, bytes).context("write temp")?;
        fs::rename(&tmp, &self.config_path).or_else(|_| {
            fs::copy(&tmp, &self.config_path)?;
            fs::remove_file(&tmp)
        }).context("commit prefs")?;
        Ok(())
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    pub fn enable_autostart(&self) -> Result<()> {
        bail!("autostart not implemented in this skeleton")
    }

    pub fn disable_autostart(&self) -> Result<()> {
        bail!("autostart not implemented in this skeleton")
    }
}

// ---- Process privilege helpers (Windows) ----

#[cfg(windows)]
pub fn is_process_elevated() -> Result<bool> {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { Ok(IsUserAnAdmin().as_bool()) }
}

#[cfg(not(windows))]
pub fn is_process_elevated() -> Result<bool> {
    bail!("Windows only")
}


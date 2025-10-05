use anyhow::{Context, Result};
use std::env;
use std::path::{Path, PathBuf};

/// Get default Firefox profile path for current platform
fn get_default_profile_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = env::var_os("APPDATA") {
            PathBuf::from(appdata)
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles")
        } else {
            PathBuf::from(".")
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env::var_os("HOME") {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Firefox")
                .join("Profiles")
        } else {
            PathBuf::from(".")
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(home) = env::var_os("HOME") {
            PathBuf::from(home).join(".mozilla").join("firefox")
        } else {
            PathBuf::from(".")
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from(".")
    }
}

/// Get the default profile path (first available profile)
pub fn get_default_profile() -> Result<PathBuf> {
    get_profile_path(None, false, Some("default".to_string()), false).or_else(|_| {
        // fallback: try to get any profile automatically
        let base = get_default_profile_path();
        let profile_ini = base.join("profiles.ini");
        if profile_ini.exists() {
            // Try to parse profiles.ini and get the first profile
            get_first_available_profile()
        } else {
            // Use base directory as profile
            Ok(base)
        }
    })
}

/// Get the first available profile from profiles.ini
fn get_first_available_profile() -> Result<PathBuf> {
    let base = get_default_profile_path();
    let profile_ini = base.join("profiles.ini");

    if !profile_ini.exists() {
        return Ok(base);
    }

    let contents = std::fs::read_to_string(&profile_ini)
        .with_context(|| format!("Failed to read {}", profile_ini.display()))?;

    // Simple profiles.ini parser - look for first Profile section
    let mut in_profile_section = false;
    let mut profile_path: Option<String> = None;
    let mut is_relative = true;

    for line in contents.lines() {
        let line = line.trim();

        if line.starts_with('[') && line.ends_with(']') {
            in_profile_section = line.starts_with("[Profile");
            continue;
        }

        if in_profile_section {
            if let Some(path_line) = line.strip_prefix("Path=") {
                profile_path = Some(path_line.to_string());
            } else if let Some(relative_line) = line.strip_prefix("IsRelative=") {
                is_relative = relative_line == "1";
            }

            // If we have both path and relative info, we can construct the full path
            if let Some(ref path) = profile_path {
                let full_path = if is_relative {
                    base.join(path)
                } else {
                    PathBuf::from(path)
                };

                if full_path.exists() {
                    return Ok(full_path);
                }
            }
        }
    }

    // Fallback to base directory
    Ok(base)
}

/// Read profiles.ini and pick profile or treat provided path as direct profile folder.
/// This mirrors the Python `get_profile` behaviour at high level.
pub fn get_profile_path(
    profile_arg: Option<&Path>,
    interactive: bool,
    choice: Option<String>,
    list: bool,
) -> Result<PathBuf> {
    let base = match profile_arg {
        Some(path) => {
            // shellexpand::tildeを標準ライブラリで置換
            let path_str = path.to_string_lossy();
            let expanded = if path_str.starts_with("~") {
                if let Ok(home) = env::var("HOME") {
                    path_str.replacen("~", &home, 1)
                } else if let Ok(userprofile) = env::var("USERPROFILE") {
                    path_str.replacen("~", &userprofile, 1)
                } else {
                    path_str.to_string()
                }
            } else {
                path_str.to_string()
            };
            PathBuf::from(expanded)
        }
        None => get_default_profile_path(),
    };

    let profile_ini = base.join("profiles.ini");
    if !profile_ini.exists() {
        // If profiles.ini missing, assume provided path is already a profile directory
        if list {
            anyhow::bail!("Listing single profile not permitted when profiles.ini is missing");
        }
        if !base.is_dir() {
            anyhow::bail!(
                "Provided profile path is not a directory: {}",
                base.display()
            );
        }
        return Ok(base.to_path_buf());
    }

    let content = std::fs::read_to_string(&profile_ini).context("failed to read profiles.ini")?;
    let mut sections = Vec::new();
    let mut current_section = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
        } else if current_section.starts_with("Profile") && line.starts_with("Path=") {
            let path = &line[5..]; // Skip "Path="
            sections.push(path.to_string());
        }
    }

    if sections.is_empty() {
        anyhow::bail!("No Profile sections found in profiles.ini");
    }

    if list {
        for _p in sections.iter() {
            let _ = ();
        }
        std::process::exit(0);
    }

    let chosen = if sections.len() == 1 {
        sections[0].clone()
    } else if let Some(c) = choice {
        let idx: usize = c.parse().context("choice must be an integer index")?;
        if idx == 0 || idx > sections.len() {
            anyhow::bail!("choice {} out of range", idx);
        }
        sections[idx - 1].clone()
    } else if !interactive {
        anyhow::bail!("Multiple profiles exist but non-interactive mode and no choice provided");
    } else {
        // simple interactive prompt (not robust) - in real code present a better UI
        let _ = ();
        for _p in sections.iter() {
            let _ = ();
        }
        use std::io::{self, Write};
        print!("Choice: ");
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let idx: usize = buf.trim().parse().context("invalid input")?;
        sections[idx - 1].clone()
    };

    let profile_path = base.join(chosen);
    if !profile_path.is_dir() {
        anyhow::bail!(
            "Resolved profile path is not a directory: {}",
            profile_path.display()
        );
    }

    Ok(profile_path)
}

//! Application configuration persistence and management.
//!
//! Handles loading and saving user preferences to a JSON config file
//! stored in the standard OS configuration directory.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tracing::{error, info, warn};

/// Application configuration structure stored in `config.json`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
    pub theme: String,
    pub default_shell: String,
    pub launch_at_startup: bool,
    pub start_locked: bool,
    #[serde(default = "default_clipboard_timeout")]
    pub clipboard_clear_timeout: u64,
    #[serde(default = "default_auto_lock_idle")]
    pub auto_lock_idle_minutes: u64,
    #[serde(default = "default_auto_lock_on_blur")]
    pub auto_lock_on_blur: bool,
}

fn default_clipboard_timeout() -> u64 {
    30
}
fn default_auto_lock_idle() -> u64 {
    15
}
fn default_auto_lock_on_blur() -> bool {
    false
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            default_shell: if cfg!(windows) {
                "powershell".to_string()
            } else {
                "bash".to_string()
            },
            launch_at_startup: false,
            start_locked: true,
            clipboard_clear_timeout: 30,
            auto_lock_idle_minutes: 15,
            auto_lock_on_blur: false,
        }
    }
}

/// Helper to get the path to the config file `config.json`
fn config_file_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("EnvGuard").join("config.json"))
}

/// Loads the application configuration from disk.
///
/// If the file does not exist or cannot be parsed, it returns the default configuration.
///
/// # Security
///
/// This config file contains no secrets and is stored in plaintext.
pub async fn load_config() -> AppConfig {
    if let Some(path) = config_file_path() {
        if path.exists() {
            match fs::read_to_string(&path).await {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(config) => return config,
                    Err(e) => error!("Failed to parse config.json: {}", e),
                },
                Err(e) => error!("Failed to read config.json: {}", e),
            }
        }
    } else {
        warn!("Could not determine config directory");
    }
    AppConfig::default()
}

pub async fn save_config(config: &AppConfig) -> Result<(), String> {
    update_startup_registration(config.launch_at_startup)?;
    if let Some(path) = config_file_path() {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        let json = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
        fs::write(&path, json).await.map_err(|e| e.to_string())?;
        info!("Saved application configuration to {:?}", path);
        Ok(())
    } else {
        Err("Could not determine config directory".to_string())
    }
}

#[cfg(windows)]
pub fn update_startup_registration(launch: bool) -> Result<(), String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_SZ,
    };

    let sub_key = windows::core::w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let mut hkey = windows::Win32::System::Registry::HKEY::default();

    unsafe {
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            sub_key,
            0,
            KEY_SET_VALUE,
            &raw mut hkey,
        );

        if status.is_err() {
            return Err(format!("Failed to open registry key: {:?}", status.err()));
        }

        let value_name = windows::core::w!("EnvGuard");

        if launch {
            let current_exe = std::env::current_exe()
                .map_err(|e| format!("Failed to get current executable path: {e}"))?;
            let quoted_path = format!("\"{}\"", current_exe.to_string_lossy());
            let path_w: Vec<u16> = quoted_path.encode_utf16().chain(std::iter::once(0)).collect();

            let raw_data = std::slice::from_raw_parts(
                path_w.as_ptr().cast::<u8>(),
                path_w.len() * 2,
            );

            let status = RegSetValueExW(
                hkey,
                value_name,
                0,
                REG_SZ,
                Some(raw_data),
            );

            let _ = RegCloseKey(hkey);

            if status.is_err() {
                return Err(format!("Failed to set registry value: {:?}", status.err()));
            }
        } else {
            let status = RegDeleteValueW(hkey, value_name);
            let _ = RegCloseKey(hkey);
            if status.is_err() {
                let err_code = status.as_ref().err().map_or(0, |e| e.code().0);
                if err_code != 2 {
                    return Err(format!("Failed to delete registry value: {:?}", status.err()));
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn update_startup_registration(launch: bool) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    let agent_dir = home.join("Library").join("LaunchAgents");
    let plist_path = agent_dir.join("com.envguard.app.plist");

    if launch {
        if !agent_dir.exists() {
            std::fs::create_dir_all(&agent_dir).map_err(|e| e.to_string())?;
        }
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.envguard.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#,
            current_exe.to_string_lossy()
        );
        std::fs::write(&plist_path, plist_content).map_err(|e| e.to_string())?;
    } else {
        if plist_path.exists() {
            std::fs::remove_file(plist_path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn update_startup_registration(launch: bool) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Cannot determine home directory")?;
    let autostart_dir = home.join(".config").join("autostart");
    let desktop_path = autostart_dir.join("envguard.desktop");

    if launch {
        if !autostart_dir.exists() {
            std::fs::create_dir_all(&autostart_dir).map_err(|e| e.to_string())?;
        }
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;
        let desktop_content = format!(
            r#"[Desktop Entry]
Type=Application
Version=1.0
Name=EnvGuard
Comment=EnvGuard Environment Variable Manager
Exec={}
StartupNotify=false
Terminal=false
"#,
            current_exe.to_string_lossy()
        );
        std::fs::write(&desktop_path, desktop_content).map_err(|e| e.to_string())?;
    } else {
        if desktop_path.exists() {
            std::fs::remove_file(desktop_path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub fn update_startup_registration(_launch: bool) -> Result<(), String> {
    Ok(())
}

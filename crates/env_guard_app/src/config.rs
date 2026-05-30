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

/// Saves the application configuration to disk.
///
/// Ensures the configuration directory exists before attempting to write the file.
///
/// # Errors
///
/// Returns `Err` if the directory cannot be created or the file cannot be written.
pub async fn save_config(config: &AppConfig) -> Result<(), String> {
    if let Some(path) = config_file_path() {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
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

use crate::state::VaultState;
use env_guard_core::env_guard::models::{Profile, RuntimeSession, SessionRules, ShellType};
use tauri::State;
use uuid::Uuid;

#[derive(serde::Serialize)]
pub struct CredentialMeta {
    pub id: String,
    pub key: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(serde::Serialize)]
pub struct ScannedFile {
    pub path: String,
    pub is_env: bool,
}

#[derive(serde::Deserialize)]
pub struct SessionRulesInput {
    pub expiration_seconds: Option<u64>,
    pub allowed_shells: Vec<String>,
    pub require_auth_on_resume: bool,
    pub ephemeral_env_drop: Option<bool>,
    pub ephemeral_env_dir: Option<String>,
    pub inherit_parent_env: Option<bool>,
}

fn map_rules_input(input: SessionRulesInput) -> SessionRules {
    let allowed_shells = input
        .allowed_shells
        .into_iter()
        .map(|s| match s.to_lowercase().as_str() {
            "bash" => ShellType::Bash,
            "zsh" => ShellType::Zsh,
            "fish" => ShellType::Fish,
            "powershell" => ShellType::PowerShell,
            "cmd" => ShellType::Cmd,
            other => ShellType::Custom(other.to_string()),
        })
        .collect();
    SessionRules {
        expiration_seconds: input.expiration_seconds,
        allowed_shells,
        require_auth_on_resume: input.require_auth_on_resume,
        ephemeral_env_drop: input.ephemeral_env_drop,
        ephemeral_env_dir: input.ephemeral_env_dir,
        inherit_parent_env: input.inherit_parent_env,
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct SecurityState {
    failed_attempts: u32,
    last_failed_attempt_ms: u64,
    failed_logs: Vec<String>,
}

async fn get_security_state(db_path: &std::path::Path) -> SecurityState {
    let sec_path = db_path.with_extension("security");
    if let Ok(data) = tokio::fs::read_to_string(&sec_path).await {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        SecurityState::default()
    }
}

async fn save_security_state(db_path: &std::path::Path, state: &SecurityState) {
    let sec_path = db_path.with_extension("security");
    if let Ok(data) = serde_json::to_string(state) {
        let _ = tokio::fs::write(&sec_path, data).await;
    }
}

#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, VaultState>,
    password: String,
) -> Result<Vec<String>, String> {
    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    let db_path = base_dir.join("EnvGuard").join("vault.db");

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut sec_state = get_security_state(&db_path).await;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);

    if sec_state.failed_attempts >= 3 {
        let delay_ms = 2u64.pow(sec_state.failed_attempts - 3) * 1000;
        if now < sec_state.last_failed_attempt_ms + delay_ms {
            let wait_sec = ((sec_state.last_failed_attempt_ms + delay_ms - now) / 1000) + 1;
            return Err(format!(
                "Too many failed attempts. Try again in {wait_sec} seconds."
            ));
        }
    }

    let engine = match env_guard_core::env_guard::envGuard::unlock(&db_path, &password).await {
        Ok(engine) => engine,
        Err(e) => {
            sec_state.failed_attempts += 1;
            sec_state.last_failed_attempt_ms = now;
            let log_entry = format!(
                "Failed unlock attempt at {}",
                chrono::Utc::now().to_rfc3339()
            );
            sec_state.failed_logs.push(log_entry);
            save_security_state(&db_path, &sec_state).await;

            let s = e.to_string();
            if s.contains("Decryption failed")
                || s.contains("Crypto error")
                || s.contains("integrity")
            {
                return Err("Incorrect master password".to_string());
            }
            return Err(s);
        }
    };

    let _ = engine.perform_crash_recovery(&db_path).await;

    let logs = sec_state.failed_logs.clone();
    if sec_state.failed_attempts > 0 {
        sec_state.failed_attempts = 0;
        sec_state.failed_logs.clear();
        save_security_state(&db_path, &sec_state).await;
    }

    let mut lock = state.inner.lock().await;
    *lock = Some(engine);
    Ok(logs)
}

#[tauri::command]
pub async fn lock_vault(state: State<'_, VaultState>) -> Result<(), String> {
    let mut lock = state.inner.lock().await;
    if let Some(engine) = lock.take() {
        engine.lock().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn wipe_vault(state: State<'_, VaultState>) -> Result<(), String> {
    let mut lock = state.inner.lock().await;
    if let Some(engine) = lock.take() {
        let _ = engine.lock().await;
    }

    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    let db_path = base_dir.join("EnvGuard").join("vault.db");
    let salt_path = db_path.with_extension("salt");

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&salt_path);
    Ok(())
}

#[tauri::command]
pub async fn is_vault_initialized() -> Result<bool, String> {
    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    let db_path = base_dir.join("EnvGuard").join("vault.db");
    Ok(db_path.exists())
}

#[tauri::command]
pub async fn create_profile(
    state: State<'_, VaultState>,
    name: String,
    description: Option<String>,
    rules: SessionRulesInput,
) -> Result<Profile, String> {
    let mapped_rules = map_rules_input(rules);
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .create_profile(&name, description.as_deref(), mapped_rules)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_profiles(state: State<'_, VaultState>) -> Result<Vec<Profile>, String> {
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine.list_profiles().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_profile(
    state: State<'_, VaultState>,
    id: String,
    name: String,
    description: Option<String>,
) -> Result<(), String> {
    let profile_id = Uuid::parse_str(&id).map_err(|_| "Invalid profile ID")?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .update_profile(profile_id, &name, description.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_profile_metadata(
    state: State<'_, VaultState>,
    id: String,
    color: Option<String>,
    tags: Vec<String>,
) -> Result<(), String> {
    let profile_id = Uuid::parse_str(&id).map_err(|_| "Invalid profile ID")?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .update_profile_metadata(profile_id, color.as_deref(), &tags)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn duplicate_profile(
    state: State<'_, VaultState>,
    id: String,
) -> Result<Profile, String> {
    let profile_uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .duplicate_profile(profile_uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_profile(state: State<'_, VaultState>, id: String) -> Result<Profile, String> {
    let profile_uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let profile_opt = engine
        .get_profile(profile_uuid)
        .await
        .map_err(|e| e.to_string())?;
    profile_opt.ok_or_else(|| "Profile not found".to_string())
}

#[tauri::command]
pub async fn update_profile_rules(
    state: State<'_, VaultState>,
    id: String,
    rules: SessionRulesInput,
) -> Result<(), String> {
    let mapped_rules = map_rules_input(rules);
    let profile_uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .update_profile_rules(profile_uuid, mapped_rules)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_profile(state: State<'_, VaultState>, id: String) -> Result<(), String> {
    let profile_uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .delete_profile(profile_uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_credential(
    state: State<'_, VaultState>,
    profile_id: String,
    key: String,
    value: String,
) -> Result<CredentialMeta, String> {
    let profile_uuid = Uuid::parse_str(&profile_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let cred = engine
        .add_credential(profile_uuid, &key, &value)
        .await
        .map_err(|e| e.to_string())?;
    Ok(CredentialMeta {
        id: cred.id.to_string(),
        key: cred.key,
        tags: cred.tags,
        created_at: cred.created_at.to_rfc3339(),
        updated_at: cred.updated_at.to_rfc3339(),
    })
}

#[tauri::command]
pub async fn list_credentials(
    state: State<'_, VaultState>,
    profile_id: String,
) -> Result<Vec<CredentialMeta>, String> {
    let profile_uuid = Uuid::parse_str(&profile_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let list = engine
        .get_credentials_metadata(profile_uuid)
        .await
        .map_err(|e| e.to_string())?;
    let result = list
        .into_iter()
        .map(|c| CredentialMeta {
            id: c.id.to_string(),
            key: c.key,
            tags: c.tags,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        })
        .collect();
    Ok(result)
}

#[tauri::command]
pub async fn decrypt_credential(
    state: State<'_, VaultState>,
    credential_id: String,
) -> Result<String, String> {
    let cred_uuid = Uuid::parse_str(&credential_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .decrypt_credential(cred_uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_credential(
    state: State<'_, VaultState>,
    credential_id: String,
) -> Result<(), String> {
    let cred_uuid = Uuid::parse_str(&credential_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .delete_credential(cred_uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_credential(
    state: State<'_, VaultState>,
    credential_id: String,
    new_value: String,
) -> Result<(), String> {
    let cred_uuid = Uuid::parse_str(&credential_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .update_credential(cred_uuid, &new_value)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn start_session(
    state: State<'_, VaultState>,
    profile_id: String,
    shell: String,
) -> Result<RuntimeSession, String> {
    let profile_uuid = Uuid::parse_str(&profile_id).map_err(|e| e.to_string())?;
    let shell_type = match shell.to_lowercase().as_str() {
        "bash" => ShellType::Bash,
        "zsh" => ShellType::Zsh,
        "fish" => ShellType::Fish,
        "powershell" => ShellType::PowerShell,
        "cmd" => ShellType::Cmd,
        other => ShellType::Custom(other.to_string()),
    };

    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .start_session(profile_uuid, shell_type)
        .await
        .map_err(|e| {
            tracing::error!("Failed to start session: {}", e);
            e.to_string()
        })
}

#[tauri::command]
pub async fn stop_session(
    state: State<'_, VaultState>,
    session_id: String,
) -> Result<Vec<String>, String> {
    let session_uuid = Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .stop_session(session_uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_active_sessions(
    state: State<'_, VaultState>,
) -> Result<Vec<RuntimeSession>, String> {
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let list = engine.list_active_sessions().await;
    Ok(list)
}

#[tauri::command]
pub async fn scan_for_env_files(
    state: State<'_, VaultState>,
    path: String,
) -> Result<Vec<ScannedFile>, String> {
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let paths = engine
        .scan_for_env_files(std::path::Path::new(&path))
        .await
        .map_err(|e| e.to_string())?;

    let result = paths
        .into_iter()
        .map(|p| {
            let path_str = p.to_string_lossy().to_string();
            let is_env = p.file_name().and_then(|s| s.to_str()).is_some_and(|name| {
                name.starts_with(".env")
                    || std::path::Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("env"))
            });
            ScannedFile {
                path: path_str,
                is_env,
            }
        })
        .collect();

    Ok(result)
}

#[tauri::command]
pub async fn get_vault_directory() -> Result<String, String> {
    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    let db_path = base_dir.join("EnvGuard");
    Ok(db_path.to_string_lossy().to_string())
}

#[tauri::command]
pub async fn get_app_config() -> Result<crate::config::AppConfig, String> {
    Ok(crate::config::load_config().await)
}

#[tauri::command]
pub async fn save_app_config(config: crate::config::AppConfig) -> Result<(), String> {
    crate::config::save_config(&config).await
}

#[tauri::command]
pub async fn open_vault_directory() -> Result<(), String> {
    if let Some(dir) = dirs::data_dir().map(|d| d.join("EnvGuard")) {
        if dir.exists() {
            #[cfg(target_os = "windows")]
            {
                std::process::Command::new("explorer")
                    .arg(&dir)
                    .spawn()
                    .map_err(|e| e.to_string())?;
            }
            #[cfg(target_os = "macos")]
            {
                std::process::Command::new("open")
                    .arg(&dir)
                    .spawn()
                    .map_err(|e| e.to_string())?;
            }
            #[cfg(target_os = "linux")]
            {
                std::process::Command::new("xdg-open")
                    .arg(&dir)
                    .spawn()
                    .map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
    }
    Err("Vault directory not found".to_string())
}

#[tauri::command]
pub fn generate_secure_token(length: usize, include_symbols: bool) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let charset_alphanumeric = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let charset_symbols =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

    let charset: &[u8] = if include_symbols {
        charset_symbols
    } else {
        charset_alphanumeric
    };

    let token: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    token
}

#[tauri::command]
pub async fn export_credentials(
    state: State<'_, VaultState>,
    credentials_to_export: Vec<(String, String)>,
    export_path: String,
) -> Result<(), String> {
    use std::fmt::Write;
    use std::fs;

    let mut exported_env = String::new();

    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;

    for (key, id_str) in credentials_to_export {
        let cred_uuid = Uuid::parse_str(&id_str).map_err(|e| e.to_string())?;
        let decrypted = engine
            .decrypt_credential(cred_uuid)
            .await
            .map_err(|e| e.to_string())?;
        let escaped_val = decrypted.replace('"', "\\\"");
        let _ = writeln!(exported_env, "{key}=\"{escaped_val}\"");
    }

    fs::write(&export_path, exported_env).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn update_credential_tags(
    state: State<'_, VaultState>,
    credential_id: String,
    tags: Vec<String>,
) -> Result<(), String> {
    let cred_uuid = Uuid::parse_str(&credential_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .update_credential_tags(cred_uuid, tags)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct CredentialHistoryItem {
    pub value: String,
    pub updated_at: String,
}

#[tauri::command]
pub async fn get_credential_history(
    state: State<'_, VaultState>,
    credential_id: String,
) -> Result<Vec<CredentialHistoryItem>, String> {
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let cred_uuid = Uuid::parse_str(&credential_id).map_err(|e| e.to_string())?;

    let hist = engine
        .get_credential_history(cred_uuid)
        .await
        .map_err(|e| e.to_string())?;
    Ok(hist
        .into_iter()
        .map(|(val, ts)| CredentialHistoryItem {
            value: val,
            updated_at: ts.to_rfc3339(),
        })
        .collect())
}

#[tauri::command]
pub async fn change_master_password(
    state: State<'_, VaultState>,
    new_password: String,
) -> Result<(), String> {
    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    let db_path = base_dir.join("EnvGuard").join("vault.db");

    let mut lock = state.inner.lock().await;
    let engine = lock.as_mut().ok_or("Vault is locked")?;

    engine
        .change_master_password(&db_path, &new_password)
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn get_keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new("envguard_vault", "master_password").map_err(|e| e.to_string())
}

#[cfg(windows)]
fn get_dpapi_path() -> Result<std::path::PathBuf, String> {
    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    Ok(base_dir.join("EnvGuard").join("vault.dpapi"))
}

#[tauri::command]
pub async fn save_password_to_keychain(password: String) -> Result<(), String> {
    let entry = get_keyring_entry()?;
    entry.set_password(&password).map_err(|e| e.to_string())?;

    #[cfg(windows)]
    {
        let dpapi_path = get_dpapi_path()?;
        if let Some(parent) = dpapi_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let encrypted = env_guard_core::env_guard::crypto::encrypt_dpapi(password.as_bytes())?;
        std::fs::write(dpapi_path, encrypted).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn get_password_from_keychain() -> Result<String, String> {
    #[cfg(windows)]
    {
        if let Ok(dpapi_path) = get_dpapi_path() {
            if dpapi_path.exists() {
                if let Ok(encrypted) = std::fs::read(&dpapi_path) {
                    if let Ok(decrypted) =
                        env_guard_core::env_guard::crypto::decrypt_dpapi(&encrypted)
                    {
                        if let Ok(s) = String::from_utf8(decrypted) {
                            return Ok(s);
                        }
                    }
                }
            }
        }
    }

    let entry = get_keyring_entry()?;
    entry.get_password().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_password_from_keychain() -> Result<(), String> {
    let entry = get_keyring_entry()?;
    let _ = entry.delete_password();

    #[cfg(windows)]
    {
        if let Ok(dpapi_path) = get_dpapi_path() {
            if dpapi_path.exists() {
                let _ = std::fs::remove_file(dpapi_path);
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn list_session_history(
    state: State<'_, VaultState>,
) -> Result<Vec<env_guard_core::env_guard::models::SessionHistoryEntry>, String> {
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .get_session_history()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_in_vscode(
    state: State<'_, VaultState>,
    profile_id: String,
) -> Result<(), String> {
    let profile_uuid = Uuid::parse_str(&profile_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine
        .spawn_process_with_env(profile_uuid, "code .")
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn spawn_process(
    state: State<'_, VaultState>,
    profile_id: String,
    command: String,
) -> Result<u32, String> {
    let profile_uuid = Uuid::parse_str(&profile_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let pid = engine
        .spawn_process_with_env(profile_uuid, &command)
        .await
        .map_err(|e| e.to_string())?;
    Ok(pid)
}

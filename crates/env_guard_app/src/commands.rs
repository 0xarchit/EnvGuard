use tauri::State;
use uuid::Uuid;
use env_guard_core::env_guard::models::{Profile, SessionRules, ShellType, RuntimeSession};
use crate::state::VaultState;

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
}

fn map_rules_input(input: SessionRulesInput) -> SessionRules {
    let allowed_shells = input.allowed_shells.into_iter().map(|s| match s.to_lowercase().as_str() {
        "bash" => ShellType::Bash,
        "zsh" => ShellType::Zsh,
        "fish" => ShellType::Fish,
        "powershell" => ShellType::PowerShell,
        "cmd" => ShellType::Cmd,
        other => ShellType::Custom(other.to_string()),
    }).collect();
    SessionRules {
        expiration_seconds: input.expiration_seconds,
        allowed_shells,
        require_auth_on_resume: input.require_auth_on_resume,
    }
}

#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, VaultState>,
    password: String,
) -> Result<(), String> {
    let base_dir = dirs::data_dir().ok_or("Cannot determine data directory")?;
    let db_path = base_dir.join("EnvGuard").join("vault.db");
    
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    
    let engine = env_guard_core::env_guard::envGuard::unlock(&db_path, &password)
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("Decryption failed") || s.contains("Crypto error") {
                "Incorrect master password".to_string()
            } else {
                s
            }
        })?;
        
    let mut lock = state.inner.lock().await;
    *lock = Some(engine);
    Ok(())
}

#[tauri::command]
pub async fn lock_vault(
    state: State<'_, VaultState>,
) -> Result<(), String> {
    let mut lock = state.inner.lock().await;
    if let Some(engine) = lock.take() {
        engine.lock().await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn wipe_vault(
    state: State<'_, VaultState>,
) -> Result<(), String> {
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
    engine.create_profile(&name, description.as_deref(), mapped_rules)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_profiles(
    state: State<'_, VaultState>,
) -> Result<Vec<Profile>, String> {
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine.list_profiles()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_profile(
    state: State<'_, VaultState>,
    id: String,
) -> Result<Profile, String> {
    let profile_uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    let profile_opt = engine.get_profile(profile_uuid)
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
    engine.update_profile_rules(profile_uuid, mapped_rules)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_profile(
    state: State<'_, VaultState>,
    id: String,
) -> Result<(), String> {
    let profile_uuid = Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine.delete_profile(profile_uuid)
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
    let cred = engine.add_credential(profile_uuid, &key, &value)
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
    let list = engine.get_credentials_metadata(profile_uuid)
        .await
        .map_err(|e| e.to_string())?;
    let result = list.into_iter().map(|c| CredentialMeta {
        id: c.id.to_string(),
        key: c.key,
        tags: c.tags,
        created_at: c.created_at.to_rfc3339(),
        updated_at: c.updated_at.to_rfc3339(),
    }).collect();
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
    engine.decrypt_credential(cred_uuid)
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
    engine.delete_credential(cred_uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_credential(
    state: State<'_, VaultState>,
    credential_id: String,
    value: String,
) -> Result<(), String> {
    let cred_uuid = Uuid::parse_str(&credential_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine.update_credential(cred_uuid, &value)
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
    engine.start_session(profile_uuid, shell_type)
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
) -> Result<(), String> {
    let session_uuid = Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    let lock = state.inner.lock().await;
    let engine = lock.as_ref().ok_or("Vault is locked")?;
    engine.stop_session(session_uuid)
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
    let paths = engine.scan_for_env_files(std::path::Path::new(&path))
        .await
        .map_err(|e| e.to_string())?;
        
    let result = paths.into_iter().map(|p| {
        let path_str = p.to_string_lossy().to_string();
        let is_env = p.file_name()
            .and_then(|s| s.to_str())
            .map(|name| name.starts_with(".env") || name.ends_with(".env"))
            .unwrap_or(false);
        ScannedFile { path: path_str, is_env }
    }).collect();
    
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

pub mod models;
pub mod errors;
pub mod crypto;
pub mod storage;
pub mod session;

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use chrono::Utc;
use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::env_guard::models::{Profile, Credential, PlaintextCredential, SessionRules, ShellType, RuntimeSession};
use crate::env_guard::errors::ControllerError;

#[allow(non_camel_case_types)]
pub struct envGuard {
    pub(crate) pool: SqlitePool,
    pub(crate) master_key: Zeroizing<[u8; 32]>,
    pub(crate) active_sessions: Arc<Mutex<HashMap<Uuid, RuntimeSession>>>,
}

#[allow(non_camel_case_types)]
impl envGuard {
    pub async fn unlock(db_path: &Path, password: &str) -> Result<Self, ControllerError> {
        let salt_path = db_path.with_extension("salt");
        let salt = if salt_path.exists() {
            std::fs::read(&salt_path)
                .map_err(|e| ControllerError::Storage(crate::env_guard::errors::StorageError::Io(e)))?
        } else {
            let s = crypto::generate_vault_salt();
            std::fs::write(&salt_path, &s)
                .map_err(|e| ControllerError::Storage(crate::env_guard::errors::StorageError::Io(e)))?;
            s.to_vec()
        };

        let master_secret = crypto::derive_master_key(password, &salt)?;
        let (db_key, master_key) = crypto::derive_split_keys(&master_secret)?;

        let hex_db_key = hex::encode(*db_key);
        let pool = storage::init_database(db_path, &hex_db_key).await?;

        Ok(Self {
            pool,
            master_key,
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn lock(self) -> Result<(), ControllerError> {
        {
            let mut sessions = self.active_sessions.lock().await;
            for (_, session) in sessions.drain() {
                if let Some(pid) = session.pid {
                    let _ = session::kill_process(pid).await;
                }
            }
        }
        self.pool.close().await;
        Ok(())
    }

    pub async fn create_profile(
        &self,
        name: &str,
        description: Option<&str>,
        session_rules: SessionRules,
    ) -> Result<Profile, ControllerError> {
        let profile = Profile {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: false,
            session_rules,
        };
        storage::store_profile(&self.pool, &profile).await?;
        Ok(profile)
    }

    pub async fn list_profiles(&self) -> Result<Vec<Profile>, ControllerError> {
        let profiles = storage::list_profiles(&self.pool).await?;
        Ok(profiles)
    }

    pub async fn delete_profile(&self, profile_id: Uuid) -> Result<(), ControllerError> {
        storage::delete_profile(&self.pool, profile_id).await?;
        Ok(())
    }

    pub async fn add_credential(
        &self,
        profile_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<Credential, ControllerError> {
        let (encrypted_value, nonce) = crypto::encrypt_value(value, &self.master_key)?;
        let cred = Credential {
            id: Uuid::new_v4(),
            profile_id,
            key: key.to_string(),
            encrypted_value,
            nonce,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: Vec::new(),
        };
        storage::store_credential(&self.pool, &cred).await?;
        Ok(cred)
    }

    pub async fn get_decrypted_credentials(
        &self,
        profile_id: Uuid,
    ) -> Result<Vec<PlaintextCredential>, ControllerError> {
        let encrypted = storage::get_credentials_for_profile(&self.pool, profile_id).await?;
        let mut results = Vec::new();
        for cred in encrypted {
            let plaintext = crypto::decrypt_value(&cred.encrypted_value, &cred.nonce, &self.master_key)?;
            results.push(PlaintextCredential {
                id: cred.id,
                profile_id: cred.profile_id,
                key: cred.key,
                value: plaintext,
            });
        }
        Ok(results)
    }

    pub async fn delete_credential(&self, credential_id: Uuid) -> Result<(), ControllerError> {
        storage::delete_credential(&self.pool, credential_id).await?;
        Ok(())
    }

    pub async fn update_credential(
        &self,
        credential_id: Uuid,
        new_value: &str,
    ) -> Result<(), ControllerError> {
        let meta_opt = storage::get_credential_metadata(&self.pool, credential_id).await?;

        if let Some((profile_id, key, created_at, tags)) = meta_opt {
            let (encrypted_value, nonce) = crypto::encrypt_value(new_value, &self.master_key)?;
            let cred = Credential {
                id: credential_id,
                profile_id,
                key,
                encrypted_value,
                nonce,
                created_at,
                updated_at: Utc::now(),
                tags,
            };
            storage::upsert_credential(&self.pool, &cred).await?;
            Ok(())
        } else {
            Err(ControllerError::Storage(crate::env_guard::errors::StorageError::CredentialNotFound(credential_id)))
        }
    }

    pub async fn start_session(
        &self,
        profile_id: Uuid,
        shell: ShellType,
    ) -> Result<RuntimeSession, ControllerError> {
        let profile_opt = storage::get_profile(&self.pool, profile_id).await?;
        let profile = match profile_opt {
            Some(p) => p,
            None => return Err(ControllerError::Storage(crate::env_guard::errors::StorageError::ProfileNotFound(profile_id))),
        };
        if !profile.session_rules.allowed_shells.is_empty() && !profile.session_rules.allowed_shells.contains(&shell) {
            return Err(ControllerError::Session(crate::env_guard::errors::SessionError::ShellNotFound(format!("{:?}", shell))));
        }
        let decrypted_creds = self.get_decrypted_credentials(profile_id).await?;
        let session = session::spawn_session(&profile, decrypted_creds, shell, &self.pool, Some(self.active_sessions.clone())).await
            .map_err(|e| ControllerError::Session(e))?;
        
        let mut sessions = self.active_sessions.lock().await;
        sessions.insert(session.id, session.clone());
        Ok(session)
    }

    pub async fn stop_session(&self, session_id: Uuid) -> Result<(), ControllerError> {
        let mut sessions = self.active_sessions.lock().await;
        if let Some(session) = sessions.remove(&session_id) {
            if let Some(pid) = session.pid {
                let _ = session::kill_process(pid).await;
            }
            session::terminate_session(session_id, &self.pool).await
                .map_err(|e| ControllerError::Session(e))?;
        }
        Ok(())
    }

    pub async fn list_active_sessions(&self) -> Vec<RuntimeSession> {
        let sessions = self.active_sessions.lock().await;
        sessions.values().cloned().collect()
    }

    pub async fn scan_for_env_files(&self, directory: &Path) -> Result<Vec<PathBuf>, ControllerError> {
        let dir = directory.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            fn scan_dir_recursive(dir: &Path, results: &mut Vec<PathBuf>) -> std::io::Result<()> {
                if dir.is_dir() {
                    for entry in std::fs::read_dir(dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() {
                            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                                if name == "target" || name == ".git" || name == "node_modules" {
                                    continue;
                                }
                            }
                            let _ = scan_dir_recursive(&path, results);
                        } else if path.is_file() {
                            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                                if name.starts_with(".env") || name.ends_with(".env") {
                                    results.push(path);
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
            scan_dir_recursive(&dir, &mut results)?;
            Ok(results)
        }).await
        .map_err(|_| ControllerError::Session(crate::env_guard::errors::SessionError::PtyError("Scan thread panicked".to_string())))?
        .map_err(|e| ControllerError::Session(crate::env_guard::errors::SessionError::Io(e)))
    }

    pub fn contains_secret_leak(
        &self,
        decrypted_creds: &[PlaintextCredential],
        log_line: &str,
    ) -> bool {
        for cred in decrypted_creds {
            let secret = &*cred.value;
            if !secret.is_empty() && log_line.contains(secret) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::env_guard::models::SessionStatus;

    #[tokio::test]
    async fn full_add_retrieve_decrypt_cycle() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault.db");
        let controller = envGuard::unlock(&db_path, "password").await.unwrap();

        let rules = SessionRules {
            expiration_seconds: None,
            allowed_shells: vec![],
            require_auth_on_resume: false,
        };
        let profile = controller.create_profile("Dev", None, rules).await.unwrap();

        controller.add_credential(profile.id, "DB_HOST", "localhost").await.unwrap();
        let decrypted = controller.get_decrypted_credentials(profile.id).await.unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].key, "DB_HOST");
        assert_eq!(*decrypted[0].value, "localhost");
    }

    #[tokio::test]
    async fn lock_clears_master_key() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault_lock.db");
        let controller = envGuard::unlock(&db_path, "password").await.unwrap();
        let pool = controller.pool.clone();
        controller.lock().await.unwrap();
        assert!(pool.is_closed());
    }

    #[tokio::test]
    async fn session_terminates_on_expiry() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("vault_expiry.db");
        let controller = envGuard::unlock(&db_path, "password").await.unwrap();

        let rules = SessionRules {
            expiration_seconds: Some(1),
            allowed_shells: vec![ShellType::Cmd, ShellType::Bash],
            require_auth_on_resume: false,
        };
        let profile = controller.create_profile("Dev", None, rules).await.unwrap();
        
        let shell = if cfg!(target_os = "windows") { ShellType::Cmd } else { ShellType::Bash };
        let session = controller.start_session(profile.id, shell).await.unwrap();
        assert_eq!(session.status, SessionStatus::Active);

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        
        let active = controller.list_active_sessions().await;
        assert_eq!(active.len(), 0);
    }
}

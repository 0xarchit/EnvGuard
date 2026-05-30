use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use chrono::Utc;
use sqlx::SqlitePool;
use crate::env_guard::models::{Profile, PlaintextCredential, RuntimeSession, ShellType, SessionStatus};
use crate::env_guard::errors::SessionError;
use crate::env_guard::storage;

pub fn resolve_shell_path(shell: &ShellType) -> Result<PathBuf, SessionError> {
    match shell {
        ShellType::Bash => {
            #[cfg(target_os = "windows")]
            {
                Ok(PathBuf::from("Bash"))
            }
            #[cfg(not(target_os = "windows"))]
            {
                which::which("bash").map_err(|_| SessionError::ShellNotFound("Bash".to_string()))
            }
        }
        ShellType::Zsh => {
            #[cfg(target_os = "macos")]
            {
                let system_zsh = PathBuf::from("/bin/zsh");
                if system_zsh.exists() {
                    return Ok(system_zsh);
                }
                which::which("zsh").map_err(|_| SessionError::ShellNotFound("Zsh".to_string()))
            }
            #[cfg(not(target_os = "macos"))]
            {
                which::which("zsh").map_err(|_| SessionError::ShellNotFound("Zsh".to_string()))
            }
        }
        ShellType::PowerShell => {
            #[cfg(target_os = "windows")]
            {
                Ok(PathBuf::from("PowerShell"))
            }
            #[cfg(not(target_os = "windows"))]
            {
                which::which("pwsh").map_err(|_| SessionError::ShellNotFound("PowerShell".to_string()))
            }
        }
        ShellType::Fish => {
            which::which("fish").map_err(|_| SessionError::ShellNotFound("Fish".to_string()))
        }
        ShellType::Cmd => {
            #[cfg(target_os = "windows")]
            {
                Ok(PathBuf::from(r"C:\Windows\System32\cmd.exe"))
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(SessionError::ShellNotFound("Cmd".to_string()))
            }
        }
        ShellType::Custom(path) => {
            let p = PathBuf::from(path);
            if p.exists() && p.is_file() {
                Ok(p)
            } else {
                Err(SessionError::ShellNotFound(path.clone()))
            }
        }
    }
}

#[cfg(unix)]
pub async fn kill_process(pid: u32) -> Result<(), SessionError> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    let raw_pid = Pid::from_raw(pid as i32);
    if let Err(e) = kill(raw_pid, Signal::SIGTERM) {
        return Err(SessionError::KillFailed(e.to_string()));
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let _ = kill(raw_pid, Signal::SIGKILL);
    Ok(())
}

#[cfg(windows)]
pub async fn kill_process(_pid: u32) -> Result<(), SessionError> {
    // No longer applicable since we don't spawn child processes
    Ok(())
}

#[cfg(windows)]
pub async fn inject_environment(credentials: &[PlaintextCredential]) -> Result<(), SessionError> {
    if credentials.is_empty() { return Ok(()); }
    let mut script = String::new();
    for cred in credentials {
        let key = cred.key.replace("'", "''");
        let val = cred.value.replace("'", "''");
        script.push_str(&format!("[Environment]::SetEnvironmentVariable('{}', '{}', 'User');\n", key, val));
    }
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&script)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(SessionError::Io)?;

    if !output.status.success() {
        return Err(SessionError::PtyError("Failed to inject environment variables".into()));
    }
    Ok(())
}

#[cfg(windows)]
pub async fn remove_environment(keys: &[String]) -> Result<(), SessionError> {
    if keys.is_empty() { return Ok(()); }
    let mut script = String::new();
    for key in keys {
        let k = key.replace("'", "''");
        script.push_str(&format!("[Environment]::SetEnvironmentVariable('{}', $null, 'User');\n", k));
    }
    use std::os::windows::process::CommandExt;
    let output = std::process::Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(&script)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(SessionError::Io)?;

    if !output.status.success() {
        return Err(SessionError::PtyError("Failed to remove environment variables".into()));
    }
    Ok(())
}

#[cfg(not(windows))]
pub async fn inject_environment(_credentials: &[PlaintextCredential]) -> Result<(), SessionError> {
    Ok(())
}

#[cfg(not(windows))]
pub async fn remove_environment(_keys: &[String]) -> Result<(), SessionError> {
    Ok(())
}

#[allow(dead_code)]
struct SessionExitStatus {
    success: bool,
    desc: String,
}

pub async fn spawn_session(
    profile: &Profile,
    credentials: Vec<PlaintextCredential>,
    shell: ShellType,
    pool: &SqlitePool,
    active_sessions: Option<Arc<Mutex<HashMap<Uuid, RuntimeSession>>>>,
) -> Result<RuntimeSession, SessionError> {
    let _shell_path = resolve_shell_path(&shell)?;
    #[cfg(windows)]
    {
        inject_environment(&credentials).await?;
    }

    let pid = None;

    let session_id = Uuid::new_v4();
    let started_at = Utc::now();
    let expires_at = profile
        .session_rules
        .expiration_seconds
        .map(|s| started_at + chrono::Duration::seconds(s as i64));

    let session = RuntimeSession {
        id: session_id,
        profile_id: profile.id,
        shell,
        started_at,
        expires_at,
        pid,
        status: SessionStatus::Active,
    };

    storage::record_session(pool, &session)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    storage::update_profile_active_status(pool, profile.id, true)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    if let Some(expires) = expires_at {
        let pool_clone = pool.clone();
        let profile_id_clone = profile.id;
        let active_sessions_clone = active_sessions.clone();
        let keys: Vec<String> = credentials.into_iter().map(|c| c.key).collect();
        
        tokio::spawn(async move {
            let dur = (expires - Utc::now()).to_std().unwrap_or(std::time::Duration::from_secs(0));
            tokio::time::sleep(dur).await;
            
            let _ = remove_environment(&keys).await;
            
            let _ = storage::update_session_status(&pool_clone, session_id, SessionStatus::Expired).await;
            let _ = storage::update_profile_active_status(&pool_clone, profile_id_clone, false).await;
            if let Some(active_map) = active_sessions_clone {
                let mut map = active_map.lock().await;
                map.remove(&session_id);
            }
        });
    }

    Ok(session)
}

pub async fn terminate_session(
    session_id: Uuid,
    pool: &SqlitePool,
) -> Result<(), SessionError> {
    let session_opt = storage::get_session_profile_and_pid(pool, session_id)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    if let Some((profile_id, pid_opt)) = session_opt {
        if let Some(pid) = pid_opt {
            let _ = kill_process(pid as u32).await;
        }

        storage::update_session_status(pool, session_id, SessionStatus::Terminated)
            .await
            .map_err(|e| SessionError::PtyError(e.to_string()))?;

        storage::update_profile_active_status(pool, profile_id, false)
            .await
            .map_err(|e| SessionError::PtyError(e.to_string()))?;
    }

    Ok(())
}

pub async fn check_session_expiration(
    session: &RuntimeSession,
    pool: &SqlitePool,
) -> Result<bool, SessionError> {
    if let Some(expire) = session.expires_at {
        if Utc::now() >= expire {
            if let Some(p) = session.pid {
                let _ = kill_process(p).await;
            }
            storage::update_session_status(pool, session.id, SessionStatus::Expired)
                .await
                .map_err(|e| SessionError::PtyError(e.to_string()))?;
            let _ = storage::update_profile_active_status(pool, session.profile_id, false).await;
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_shell_path_fails_on_custom_invalid() {
        let shell = ShellType::Custom("nonexistent_shell_binary_foo_bar".to_string());
        let res = resolve_shell_path(&shell);
        assert!(res.is_err());
    }

    #[test]
    fn test_resolve_shell_path_resolves_standard_cmd_or_bash() {
        #[cfg(target_os = "windows")]
        {
            let res = resolve_shell_path(&ShellType::Cmd);
            assert!(res.is_ok());
        }
        #[cfg(not(target_os = "windows"))]
        {
            let res = resolve_shell_path(&ShellType::Bash);
            if res.is_ok() {
                assert!(res.unwrap().exists());
            }
        }
    }
}


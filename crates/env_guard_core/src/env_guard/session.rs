use crate::env_guard::errors::SessionError;
use crate::env_guard::models::{
    PlaintextCredential, Profile, RuntimeSession, SessionStatus, ShellType,
};
use crate::env_guard::storage;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use std::fmt::Write;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

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
                which::which("pwsh")
                    .map_err(|_| SessionError::ShellNotFound("PowerShell".to_string()))
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
#[allow(clippy::unused_async)]
pub async fn kill_process(_pid: u32) -> Result<(), SessionError> {
    Ok(())
}

#[cfg(windows)]
pub async fn inject_environment(credentials: &[PlaintextCredential]) -> Result<(), SessionError> {
    if credentials.is_empty() {
        return Ok(());
    }
    let mut script = String::new();
    for cred in credentials {
        let key = cred.key.replace('\'', "''");
        let val = cred.value.replace('\'', "''");
        let _ = writeln!(script, "[Environment]::SetEnvironmentVariable('{key}', '{val}', 'User');");
    }
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(script)
            .creation_flags(0x0800_0000)
            .output()
    })
    .await
    .map_err(|e| SessionError::PtyError(e.to_string()))?
    .map_err(SessionError::Io)?;

    if !output.status.success() {
        return Err(SessionError::PtyError(
            "Failed to inject environment variables".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub async fn remove_environment(keys: &[String]) -> Result<(), SessionError> {
    if keys.is_empty() {
        return Ok(());
    }
    let mut script = String::new();
    for key in keys {
        let k = key.replace('\'', "''");
        let _ = writeln!(script, "[Environment]::SetEnvironmentVariable('{k}', $null, 'User');");
    }
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(script)
            .creation_flags(0x0800_0000)
            .output()
    })
    .await
    .map_err(|e| SessionError::PtyError(e.to_string()))?
    .map_err(SessionError::Io)?;

    if !output.status.success() {
        return Err(SessionError::PtyError(
            "Failed to remove environment variables".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub async fn audit_environment(keys: &[String]) -> Result<Vec<String>, SessionError> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut script = String::new();
    script.push_str("$leaked = @();\n");
    for key in keys {
        let k = key.replace('\'', "''");
        let _ = writeln!(script, "if ([Environment]::GetEnvironmentVariable('{k}', 'User')) {{ $leaked += '{k}' }}");
    }
    script.push_str("if ($leaked.Count -gt 0) { Write-Output ($leaked -join ',') }\n");

    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(script)
            .creation_flags(0x0800_0000)
            .output()
    })
    .await
    .map_err(|e| SessionError::PtyError(e.to_string()))?
    .map_err(SessionError::Io)?;

    let leaked_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if leaked_str.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(leaked_str.split(',').map(std::string::ToString::to_string).collect())
    }
}

#[cfg(not(windows))]
#[allow(clippy::unused_async)]
pub async fn inject_environment(_credentials: &[PlaintextCredential]) -> Result<(), SessionError> {
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unused_async)]
pub async fn remove_environment(_keys: &[String]) -> Result<(), SessionError> {
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unused_async)]
pub async fn audit_environment(_keys: &[String]) -> Result<Vec<String>, SessionError> {
    Ok(Vec::new())
}

pub fn write_ephemeral_env(
    credentials: &[PlaintextCredential],
    target_dir: &str,
    session_id: Uuid,
) -> Result<PathBuf, SessionError> {
    let dir_path = std::path::PathBuf::from(target_dir);
    if !dir_path.exists() {
        return Err(SessionError::PtyError(format!("Target directory does not exist: {target_dir}")));
    }
    let file_name = format!(".envguard_ephemeral_{session_id}.env");
    let file_path = dir_path.join(file_name);

    let mut content = String::new();
    for cred in credentials {
        let escaped_val = cred.value.replace('"', "\\\"");
        let _ = writeln!(content, "{}=\"{escaped_val}\"", cred.key);
    }

    std::fs::write(&file_path, content).map_err(SessionError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&file_path).map_err(SessionError::Io)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&file_path, perms).map_err(SessionError::Io)?;
    }

    #[cfg(windows)]
    {
        let _ = std::process::Command::new("attrib")
            .arg("+h")
            .arg(&file_path)
            .status();
    }

    Ok(file_path)
}

pub fn cleanup_ephemeral_env(file_path: &str) -> Result<(), SessionError> {
    let p = std::path::Path::new(file_path);
    if p.exists() {
        std::fs::remove_file(p).map_err(SessionError::Io)?;
    }
    Ok(())
}

pub async fn spawn_session<S>(
    profile: &Profile,
    credentials: Vec<PlaintextCredential>,
    shell: ShellType,
    pool: &SqlitePool,
    active_sessions: Option<Arc<Mutex<HashMap<Uuid, RuntimeSession, S>>>>,
) -> Result<RuntimeSession, SessionError>
where
    S: std::hash::BuildHasher + Send + Sync + 'static,
{
    let _shell_path = resolve_shell_path(&shell)?;

    let session_id = Uuid::new_v4();
    let mut ephemeral_env_path = None;

    if let Some(true) = profile.session_rules.ephemeral_env_drop {
        if let Some(ref dir) = profile.session_rules.ephemeral_env_dir {
            let path = write_ephemeral_env(&credentials, dir, session_id)?;
            ephemeral_env_path = Some(path.to_string_lossy().to_string());
        }
    }

    let inherit = profile.session_rules.inherit_parent_env.unwrap_or(true);

    #[cfg(windows)]
    {
        if inherit {
            inject_environment(&credentials).await?;
        }
    }

    let pid = None;
    let started_at = Utc::now();
    let expires_at = profile
        .session_rules
        .expiration_seconds
        .map(|s| started_at + chrono::Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)));

    let session = RuntimeSession {
        id: session_id,
        profile_id: profile.id,
        shell,
        started_at,
        expires_at,
        pid,
        status: SessionStatus::Active,
        ephemeral_env_path: ephemeral_env_path.clone(),
    };

    storage::record_session(pool, &session)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    let _ = storage::store_session_history_start(pool, session_id, profile.id, &session.shell, started_at).await;

    storage::update_profile_active_status(pool, profile.id, true)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    if let Some(expires) = expires_at {
        let pool_clone = pool.clone();
        let profile_id_clone = profile.id;
        let active_sessions_clone = active_sessions.clone();
        let keys: Vec<String> = credentials.into_iter().map(|c| c.key).collect();
        let eph_path = ephemeral_env_path.clone();

        tokio::spawn(async move {
            let dur = (expires - Utc::now())
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(0));
            tokio::time::sleep(dur).await;

            let _ = remove_environment(&keys).await;

            if let Some(ref path) = eph_path {
                let _ = cleanup_ephemeral_env(path);
            }

            let _ = storage::update_session_status(&pool_clone, session_id, SessionStatus::Expired)
                .await;
            let _ = storage::store_session_history_stop(&pool_clone, session_id, Utc::now(), Some(0)).await;
            let _ =
                storage::update_profile_active_status(&pool_clone, profile_id_clone, false).await;
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

    if let Some((profile_id, pid_opt, ephemeral_path_opt)) = session_opt {
        if let Some(pid) = pid_opt {
            if let Ok(pid_u32) = u32::try_from(pid) {
                let _ = kill_process(pid_u32).await;
            }
        }

        if let Some(ref path) = ephemeral_path_opt {
            let _ = cleanup_ephemeral_env(path);
        }

        storage::update_session_status(pool, session_id, SessionStatus::Terminated)
            .await
            .map_err(|e| SessionError::PtyError(e.to_string()))?;

        let _ = storage::store_session_history_stop(pool, session_id, Utc::now(), Some(0)).await;

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
            if let Some(ref path) = session.ephemeral_env_path {
                let _ = cleanup_ephemeral_env(path);
            }
            storage::update_session_status(pool, session.id, SessionStatus::Expired)
                .await
                .map_err(|e| SessionError::PtyError(e.to_string()))?;
            let _ = storage::store_session_history_stop(pool, session.id, Utc::now(), Some(0)).await;
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

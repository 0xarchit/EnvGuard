use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use chrono::Utc;
use sqlx::{SqlitePool, Row};
use portable_pty::{native_pty_system, PtySize, CommandBuilder};
use crate::env_guard::models::{Profile, PlaintextCredential, RuntimeSession, ShellType, SessionStatus};
use crate::env_guard::errors::SessionError;
use crate::env_guard::storage;

pub fn resolve_shell_path(shell: &ShellType) -> Result<PathBuf, SessionError> {
    match shell {
        ShellType::Bash => {
            #[cfg(target_os = "windows")]
            {
                let candidates = [
                    r"C:\Program Files\Git\bin\bash.exe",
                    r"C:\Program Files (x86)\Git\bin\bash.exe",
                ];
                for p in candidates {
                    let path = PathBuf::from(p);
                    if path.exists() {
                        return Ok(path);
                    }
                }
                Err(SessionError::ShellNotFound("Bash".to_string()))
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
                which::which("pwsh")
                    .or_else(|_| which::which("powershell"))
                    .map_err(|_| SessionError::ShellNotFound("PowerShell".to_string()))
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
pub async fn kill_process(pid: u32) -> Result<(), SessionError> {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    use windows::Win32::Foundation::CloseHandle;
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| SessionError::KillFailed(e.to_string()))?;
        let res = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        if res.is_err() {
            return Err(SessionError::KillFailed("TerminateProcess failed".to_string()));
        }
    }
    Ok(())
}

pub async fn spawn_session(
    profile: &Profile,
    credentials: Vec<PlaintextCredential>,
    shell: ShellType,
    pool: &SqlitePool,
    active_sessions: Option<Arc<Mutex<HashMap<Uuid, RuntimeSession>>>>,
) -> Result<RuntimeSession, SessionError> {
    let shell_path = resolve_shell_path(&shell)?;
    let whitelist = [
        "PATH",
        "TERM",
        "HOME",
        "USER",
        "USERNAME",
        "SystemRoot",
        "SystemDrive",
        "COMSPEC",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LANG",
        "LC_ALL",
    ];

    let mut envs = HashMap::new();
    for &w in &whitelist {
        if let Ok(val) = std::env::var(w) {
            envs.insert(w.to_string(), val);
        }
    }
    for cred in &credentials {
        envs.insert(cred.key.clone(), (*cred.value).clone());
    }

    let pty_system = native_pty_system();
    let pair_opt = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    });

    let (pid, child_waiter) = match pair_opt {
        Ok(pair) => {
            let mut cmd = CommandBuilder::new(&shell_path);
            for (key, _) in std::env::vars() {
                cmd.env_remove(key);
            }
            for (key, val) in envs {
                cmd.env(key, val);
            }
            let mut child = pair
                .slave
                .spawn_command(cmd)
                .map_err(|e| SessionError::PtyError(e.to_string()))?;
            let pid = child.process_id();
            let waiter: Box<dyn FnOnce() -> Result<std::process::ExitStatus, std::io::Error> + Send + 'static> = Box::new(move || child.wait());
            (pid, waiter)
        }
        Err(_) => {
            let mut cmd = std::process::Command::new(&shell_path);
            cmd.env_clear();
            for (key, val) in envs {
                cmd.env(key, val);
            }
            let mut child = cmd.spawn().map_err(|e| SessionError::Io(e))?;
            let pid = child.id();
            let waiter: Box<dyn FnOnce() -> Result<std::process::ExitStatus, std::io::Error> + Send + 'static> = Box::new(move || child.wait());
            (Some(pid), waiter)
        }
    };

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

    sqlx::query("UPDATE profiles SET is_active = 1 WHERE id = ?")
        .bind(profile.id.to_string())
        .execute(pool)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    let pool_clone = pool.clone();
    let expires_at_clone = expires_at;
    let profile_id_clone = profile.id;
    let active_sessions_clone = active_sessions.clone();
    tokio::spawn(async move {
        let mut exit_fut = tokio::task::spawn_blocking(move || child_waiter());
        let final_status = if let Some(expires) = expires_at_clone {
            let dur = (expires - Utc::now()).to_std().unwrap_or(std::time::Duration::from_secs(0));
            tokio::select! {
                res = &mut exit_fut => {
                    match res {
                        Ok(Ok(status)) if status.success() => SessionStatus::Terminated,
                        Ok(Ok(status)) => SessionStatus::Failed(format!("Exit code: {:?}", status)),
                        _ => SessionStatus::Failed("Process exited abnormally".to_string()),
                    }
                }
                _ = tokio::time::sleep(dur) => {
                    if let Some(p) = pid {
                        let _ = kill_process(p).await;
                    }
                    SessionStatus::Expired
                }
            }
        } else {
            let res = exit_fut.await;
            match res {
                Ok(Ok(status)) if status.success() => SessionStatus::Terminated,
                Ok(Ok(status)) => SessionStatus::Failed(format!("Exit code: {:?}", status)),
                _ => SessionStatus::Failed("Process exited abnormally".to_string()),
            }
        };
        let _ = storage::update_session_status(&pool_clone, session_id, final_status).await;
        let _ = sqlx::query("UPDATE profiles SET is_active = 0 WHERE id = ?")
            .bind(profile_id_clone.to_string())
            .execute(&pool_clone)
            .await;
        if let Some(active_map) = active_sessions_clone {
            let mut map = active_map.lock().await;
            map.remove(&session_id);
        }
    });

    Ok(session)
}

pub async fn terminate_session(
    session_id: Uuid,
    pool: &SqlitePool,
) -> Result<(), SessionError> {
    let row = sqlx::query("SELECT profile_id, pid FROM sessions WHERE id = ?")
        .bind(session_id.to_string())
        .fetch_optional(pool)
        .await
        .map_err(|e| SessionError::PtyError(e.to_string()))?;

    if let Some(r) = row {
        let profile_id_str: String = r.get(0);
        let pid_opt: Option<i64> = r.get(1);

        if let Some(pid) = pid_opt {
            let _ = kill_process(pid as u32).await;
        }

        sqlx::query("UPDATE sessions SET status = ? WHERE id = ?")
            .bind(serde_json::to_string(&SessionStatus::Terminated).unwrap())
            .bind(session_id.to_string())
            .execute(pool)
            .await
            .map_err(|e| SessionError::PtyError(e.to_string()))?;

        sqlx::query("UPDATE profiles SET is_active = 0 WHERE id = ?")
            .bind(profile_id_str)
            .execute(pool)
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
            let _ = sqlx::query("UPDATE profiles SET is_active = 0 WHERE id = ?")
                .bind(session.profile_id.to_string())
                .execute(pool)
                .await;
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


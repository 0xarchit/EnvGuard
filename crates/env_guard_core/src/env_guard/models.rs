use chrono::{DateTime, Utc};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Cmd,
    Custom(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SessionRules {
    pub expiration_seconds: Option<u64>,
    pub allowed_shells: Vec<ShellType>,
    pub require_auth_on_resume: bool,
    pub ephemeral_env_drop: Option<bool>,
    pub ephemeral_env_dir: Option<String>,
    pub inherit_parent_env: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub color: Option<String>,
    pub tags: Vec<String>,
    pub is_active: bool,
    pub session_rules: SessionRules,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Credential {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub key: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

pub struct PlaintextCredential {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub key: String,
    pub value: Zeroizing<String>,
}

impl fmt::Debug for PlaintextCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextCredential")
            .field("id", &self.id)
            .field("profile_id", &self.profile_id)
            .field("key", &self.key)
            .field("value", &"<REDACTED>")
            .finish()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Expired,
    Terminated,
    Failed(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RuntimeSession {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub shell: ShellType,
    pub started_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub pid: Option<u32>,
    pub status: SessionStatus,
    pub ephemeral_env_path: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionHistoryEntry {
    pub session_id: String,
    pub profile_id: String,
    pub profile_name: String,
    pub shell: String,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub exit_code: Option<i32>,
}

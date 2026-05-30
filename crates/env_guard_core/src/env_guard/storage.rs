use std::path::Path;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, Row};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use crate::env_guard::models::{Profile, Credential, RuntimeSession, SessionRules, ShellType, SessionStatus};
use crate::env_guard::errors::StorageError;

pub async fn init_database(path: &Path, db_key: &str) -> Result<SqlitePool, StorageError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .pragma("key", format!("'{}'", db_key))
        .pragma("foreign_keys", "ON");
    let pool = SqlitePool::connect_with(options).await?;
    
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY,
            salt BLOB NOT NULL,
            created_at TEXT NOT NULL
        );"
    ).execute(&pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            session_rules TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT,
            color TEXT,
            tags TEXT NOT NULL DEFAULT '[]'
        );"
    ).execute(&pool).await?;

    // Schema migration for old vaults
    let table_info = sqlx::query("PRAGMA table_info(profiles)").fetch_all(&pool).await?;
    let mut has_last_used = false;
    let mut has_color = false;
    let mut has_tags = false;
    for row in table_info {
        let name: String = row.get("name");
        if name == "last_used_at" { has_last_used = true; }
        if name == "color" { has_color = true; }
        if name == "tags" { has_tags = true; }
    }
    if !has_last_used {
        sqlx::query("ALTER TABLE profiles ADD COLUMN last_used_at TEXT").execute(&pool).await?;
    }
    if !has_color {
        sqlx::query("ALTER TABLE profiles ADD COLUMN color TEXT").execute(&pool).await?;
    }
    if !has_tags {
        sqlx::query("ALTER TABLE profiles ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'").execute(&pool).await?;
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            key TEXT NOT NULL,
            encrypted_value BLOB NOT NULL,
            nonce BLOB NOT NULL,
            tags TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(profile_id, key)
        );"
    ).execute(&pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
            shell TEXT NOT NULL,
            started_at TEXT NOT NULL,
            expires_at TEXT,
            pid INTEGER,
            status TEXT NOT NULL
        );"
    ).execute(&pool).await?;

    Ok(pool)
}


pub async fn store_profile(pool: &SqlitePool, profile: &Profile) -> Result<(), StorageError> {
    let rules_str = serde_json::to_string(&profile.session_rules)?;
    let tags_str = serde_json::to_string(&profile.tags)?;
    let last_used_str = profile.last_used_at.map(|dt| dt.to_rfc3339());
    sqlx::query(
        "INSERT INTO profiles (id, name, description, session_rules, is_active, created_at, updated_at, last_used_at, color, tags)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(profile.id.to_string())
    .bind(&profile.name)
    .bind(&profile.description)
    .bind(rules_str)
    .bind(if profile.is_active { 1 } else { 0 })
    .bind(profile.created_at.to_rfc3339())
    .bind(profile.updated_at.to_rfc3339())
    .bind(last_used_str)
    .bind(&profile.color)
    .bind(tags_str)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_profile(pool: &SqlitePool, id: Uuid) -> Result<Option<Profile>, StorageError> {
    let row = sqlx::query("SELECT id, name, description, session_rules, is_active, created_at, updated_at, last_used_at, color, tags FROM profiles WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    if let Some(r) = row {
        let id_str: String = r.get(0);
        let name: String = r.get(1);
        let description: Option<String> = r.get(2);
        let rules_str: String = r.get(3);
        let is_active_int: i32 = r.get(4);
        let created_str: String = r.get(5);
        let updated_str: String = r.get(6);
        let last_used_str: Option<String> = r.get(7);
        let color: Option<String> = r.get(8);
        let tags_str: String = r.get(9);

        let rules: SessionRules = serde_json::from_str(&rules_str)?;
        let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
        let created_at = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339(&updated_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let last_used_at = match last_used_str {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        Ok(Some(Profile {
            id: Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            name,
            description,
            created_at,
            updated_at,
            last_used_at,
            color,
            tags,
            is_active: is_active_int != 0,
            session_rules: rules,
        }))
    } else {
        Ok(None)
    }
}

pub async fn list_profiles(pool: &SqlitePool) -> Result<Vec<Profile>, StorageError> {
    let rows = sqlx::query("SELECT id, name, description, session_rules, is_active, created_at, updated_at, last_used_at, color, tags FROM profiles")
        .fetch_all(pool)
        .await?;
    let mut results = Vec::new();
    for r in rows {
        let id_str: String = r.get(0);
        let name: String = r.get(1);
        let description: Option<String> = r.get(2);
        let rules_str: String = r.get(3);
        let is_active_int: i32 = r.get(4);
        let created_str: String = r.get(5);
        let updated_str: String = r.get(6);
        let last_used_str: Option<String> = r.get(7);
        let color: Option<String> = r.get(8);
        let tags_str: String = r.get(9);

        let rules: SessionRules = serde_json::from_str(&rules_str)?;
        let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
        let created_at = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339(&updated_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let last_used_at = match last_used_str {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        results.push(Profile {
            id: Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            name,
            description,
            created_at,
            updated_at,
            last_used_at,
            color,
            tags,
            is_active: is_active_int != 0,
            session_rules: rules,
        });
    }
    Ok(results)
}

pub async fn delete_profile(pool: &SqlitePool, id: Uuid) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM profiles WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_profile(
    pool: &SqlitePool,
    id: Uuid,
    name: &str,
    description: Option<&str>,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE profiles SET name = ?, description = ?, updated_at = ? WHERE id = ?"
    )
    .bind(name)
    .bind(description)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_profile_metadata(
    pool: &SqlitePool,
    id: Uuid,
    color: Option<&str>,
    tags: &[String],
) -> Result<(), StorageError> {
    let tags_str = serde_json::to_string(tags)?;
    sqlx::query(
        "UPDATE profiles SET color = ?, tags = ?, updated_at = ? WHERE id = ?"
    )
    .bind(color)
    .bind(tags_str)
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_profile_last_used(
    pool: &SqlitePool,
    id: Uuid,
) -> Result<(), StorageError> {
    sqlx::query(
        "UPDATE profiles SET last_used_at = ? WHERE id = ?"
    )
    .bind(chrono::Utc::now().to_rfc3339())
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn store_credential(pool: &SqlitePool, cred: &Credential) -> Result<(), StorageError> {
    let tags_str = serde_json::to_string(&cred.tags)?;
    sqlx::query(
        "INSERT INTO credentials (id, profile_id, key, encrypted_value, nonce, tags, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(cred.id.to_string())
    .bind(cred.profile_id.to_string())
    .bind(&cred.key)
    .bind(&cred.encrypted_value)
    .bind(&cred.nonce)
    .bind(tags_str)
    .bind(cred.created_at.to_rfc3339())
    .bind(cred.updated_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_credentials_for_profile(
    pool: &SqlitePool,
    profile_id: Uuid,
) -> Result<Vec<Credential>, StorageError> {
    let rows = sqlx::query("SELECT id, profile_id, key, encrypted_value, nonce, tags, created_at, updated_at FROM credentials WHERE profile_id = ?")
        .bind(profile_id.to_string())
        .fetch_all(pool)
        .await?;
    let mut results = Vec::new();
    for r in rows {
        let id_str: String = r.get(0);
        let p_id_str: String = r.get(1);
        let key: String = r.get(2);
        let encrypted_value: Vec<u8> = r.get(3);
        let nonce: Vec<u8> = r.get(4);
        let tags_str: String = r.get(5);
        let created_str: String = r.get(6);
        let updated_str: String = r.get(7);

        let tags: Vec<String> = serde_json::from_str(&tags_str)?;
        let created_at = DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339(&updated_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);

        results.push(Credential {
            id: Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            profile_id: Uuid::parse_str(&p_id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            key,
            encrypted_value,
            nonce,
            created_at,
            updated_at,
            tags,
        });
    }
    Ok(results)
}

pub async fn delete_credential(pool: &SqlitePool, id: Uuid) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM credentials WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn upsert_credential(pool: &SqlitePool, cred: &Credential) -> Result<(), StorageError> {
    let tags_str = serde_json::to_string(&cred.tags)?;
    sqlx::query(
        "INSERT INTO credentials (id, profile_id, key, encrypted_value, nonce, tags, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(profile_id, key) DO UPDATE SET
             encrypted_value = excluded.encrypted_value,
             nonce = excluded.nonce,
             tags = excluded.tags,
             updated_at = excluded.updated_at"
    )
    .bind(cred.id.to_string())
    .bind(cred.profile_id.to_string())
    .bind(&cred.key)
    .bind(&cred.encrypted_value)
    .bind(&cred.nonce)
    .bind(tags_str)
    .bind(cred.created_at.to_rfc3339())
    .bind(cred.updated_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn record_session(pool: &SqlitePool, session: &RuntimeSession) -> Result<(), StorageError> {
    let shell_str = serde_json::to_string(&session.shell)?;
    let status_str = serde_json::to_string(&session.status)?;
    sqlx::query(
        "INSERT INTO sessions (id, profile_id, shell, started_at, expires_at, pid, status)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(session.id.to_string())
    .bind(session.profile_id.to_string())
    .bind(shell_str)
    .bind(session.started_at.to_rfc3339())
    .bind(session.expires_at.map(|d| d.to_rfc3339()))
    .bind(session.pid.map(|p| p as i32))
    .bind(status_str)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_session_status(
    pool: &SqlitePool,
    session_id: Uuid,
    status: SessionStatus,
) -> Result<(), StorageError> {
    let status_str = serde_json::to_string(&status)?;
    sqlx::query("UPDATE sessions SET status = ? WHERE id = ?")
        .bind(status_str)
        .bind(session_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_active_session(
    pool: &SqlitePool,
    profile_id: Uuid,
) -> Result<Option<RuntimeSession>, StorageError> {
    let active_status_str = serde_json::to_string(&SessionStatus::Active)?;
    let row = sqlx::query("SELECT id, profile_id, shell, started_at, expires_at, pid, status FROM sessions WHERE profile_id = ? AND status = ? LIMIT 1")
        .bind(profile_id.to_string())
        .bind(active_status_str)
        .fetch_optional(pool)
        .await?;
    if let Some(r) = row {
        let id_str: String = r.get(0);
        let p_id_str: String = r.get(1);
        let shell_str: String = r.get(2);
        let started_str: String = r.get(3);
        let expires_str: Option<String> = r.get(4);
        let pid_int: Option<i32> = r.get(5);
        let status_str: String = r.get(6);

        let shell: ShellType = serde_json::from_str(&shell_str)?;
        let status: SessionStatus = serde_json::from_str(&status_str)?;
        let started_at = DateTime::parse_from_rfc3339(&started_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let expires_at = if let Some(ref d) = expires_str {
            Some(DateTime::parse_from_rfc3339(d)
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
                .with_timezone(&Utc))
        } else {
            None
        };

        Ok(Some(RuntimeSession {
            id: Uuid::parse_str(&id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            profile_id: Uuid::parse_str(&p_id_str).map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            shell,
            started_at,
            expires_at,
            pid: pid_int.map(|p| p as u32),
            status,
        }))
    } else {
        Ok(None)
    }
}

pub async fn get_credential_metadata(
    pool: &SqlitePool,
    id: Uuid,
) -> Result<Option<(Uuid, String, DateTime<Utc>, Vec<String>)>, StorageError> {
    let row = sqlx::query("SELECT profile_id, key, created_at, tags FROM credentials WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    if let Some(r) = row {
        let profile_id_str: String = r.get(0);
        let key: String = r.get(1);
        let created_str: String = r.get(2);
        let tags_str: String = r.get(3);

        let profile_id = Uuid::parse_str(&profile_id_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?
            .with_timezone(&Utc);
        let tags: Vec<String> = serde_json::from_str(&tags_str)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

        Ok(Some((profile_id, key, created_at, tags)))
    } else {
        Ok(None)
    }
}

pub async fn update_profile_active_status(
    pool: &SqlitePool,
    profile_id: Uuid,
    is_active: bool,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE profiles SET is_active = ? WHERE id = ?")
        .bind(if is_active { 1 } else { 0 })
        .bind(profile_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_session_profile_and_pid(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<Option<(Uuid, Option<i64>)>, StorageError> {
    let row = sqlx::query("SELECT profile_id, pid FROM sessions WHERE id = ?")
        .bind(session_id.to_string())
        .fetch_optional(pool)
        .await?;
    if let Some(r) = row {
        let profile_id_str: String = r.get(0);
        let pid: Option<i64> = r.get(1);
        let profile_id = Uuid::parse_str(&profile_id_str)
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        Ok(Some((profile_id, pid)))
    } else {
        Ok(None)
    }
}

pub async fn get_encrypted_credential_value(
    pool: &SqlitePool,
    id: Uuid,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, StorageError> {
    let row = sqlx::query("SELECT encrypted_value, nonce FROM credentials WHERE id = ?")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await?;
    if let Some(r) = row {
        let enc_val: Vec<u8> = r.get(0);
        let nonce: Vec<u8> = r.get(1);
        Ok(Some((enc_val, nonce)))
    } else {
        Ok(None)
    }
}

pub async fn update_profile_rules(
    pool: &SqlitePool,
    profile_id: Uuid,
    rules: &SessionRules,
) -> Result<(), StorageError> {
    let rules_str = serde_json::to_string(rules)?;
    sqlx::query("UPDATE profiles SET session_rules = ?, updated_at = ? WHERE id = ?")
        .bind(rules_str)
        .bind(Utc::now().to_rfc3339())
        .bind(profile_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn create_and_retrieve_profile() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let pool = init_database(&db_path, "pass").await.unwrap();

        let profile_id = Uuid::new_v4();
        let rules = SessionRules {
            expiration_seconds: Some(3600),
            allowed_shells: vec![ShellType::Bash],
            require_auth_on_resume: false,
        };
        let profile = Profile {
            id: profile_id,
            name: "Test Profile".to_string(),
            description: Some("Test Desc".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: false,
            session_rules: rules,
        };

        store_profile(&pool, &profile).await.unwrap();
        let fetched = get_profile(&pool, profile_id).await.unwrap().unwrap();
        assert_eq!(fetched.id, profile.id);
        assert_eq!(fetched.name, profile.name);
        assert_eq!(fetched.session_rules.expiration_seconds, Some(3600));
    }

    #[tokio::test]
    async fn credential_upsert_updates_existing() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_cred.db");
        let pool = init_database(&db_path, "pass").await.unwrap();

        let profile_id = Uuid::new_v4();
        let rules = SessionRules {
            expiration_seconds: None,
            allowed_shells: vec![],
            require_auth_on_resume: false,
        };
        let profile = Profile {
            id: profile_id,
            name: "P1".to_string(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: false,
            session_rules: rules,
        };
        store_profile(&pool, &profile).await.unwrap();

        let cred_id = Uuid::new_v4();
        let cred = Credential {
            id: cred_id,
            profile_id,
            key: "API_KEY".to_string(),
            encrypted_value: vec![1, 2, 3],
            nonce: vec![4; 12],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec![],
        };
        store_credential(&pool, &cred).await.unwrap();

        let mut updated = cred.clone();
        updated.encrypted_value = vec![9, 9, 9];
        upsert_credential(&pool, &updated).await.unwrap();

        let list = get_credentials_for_profile(&pool, profile_id).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].encrypted_value, vec![9, 9, 9]);
    }

    #[tokio::test]
    async fn cascade_delete_removes_credentials() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_cascade.db");
        let pool = init_database(&db_path, "pass").await.unwrap();

        let profile_id = Uuid::new_v4();
        let rules = SessionRules {
            expiration_seconds: None,
            allowed_shells: vec![],
            require_auth_on_resume: false,
        };
        let profile = Profile {
            id: profile_id,
            name: "P1".to_string(),
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_active: false,
            session_rules: rules,
        };
        store_profile(&pool, &profile).await.unwrap();

        let cred = Credential {
            id: Uuid::new_v4(),
            profile_id,
            key: "K".to_string(),
            encrypted_value: vec![1],
            nonce: vec![2; 12],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec![],
        };
        store_credential(&pool, &cred).await.unwrap();

        delete_profile(&pool, profile_id).await.unwrap();

        let list = get_credentials_for_profile(&pool, profile_id).await.unwrap();
        assert_eq!(list.len(), 0);
    }
}

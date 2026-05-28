use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Migration error: {0}")]
    Migration(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Profile not found: {0}")]
    ProfileNotFound(Uuid),
    #[error("Credential not found: {0}")]
    CredentialNotFound(Uuid),
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Shell not found: {0}")]
    ShellNotFound(String),
    #[error("PTY error: {0}")]
    PtyError(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Process kill failed: {0}")]
    KillFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Session error: {0}")]
    Session(#[from] SessionError),
    #[error("Vault is locked")]
    VaultLocked,
    #[error("Session already active for profile {0}")]
    SessionAlreadyActive(Uuid),
}

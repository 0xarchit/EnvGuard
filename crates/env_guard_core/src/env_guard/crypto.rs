use crate::env_guard::errors::CryptoError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn generate_vault_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params =
        Params::new(65536, 3, 4, Some(32)).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::default(), params);
    let mut derived = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(Zeroizing::new(derived))
}

#[allow(clippy::type_complexity)]
pub fn derive_split_keys(
    master_secret: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), CryptoError> {
    let hk =
        Hkdf::<Sha256>::from_prk(master_secret).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let mut db_key = [0u8; 32];
    let mut master_key = [0u8; 32];
    hk.expand(b"EnvGuard SQLCipher Database Key", &mut db_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    hk.expand(b"EnvGuard Credential Master Key", &mut master_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok((Zeroizing::new(db_key), Zeroizing::new(master_key)))
}

pub fn encrypt_value(plaintext: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt_value(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    key: &[u8; 32],
) -> Result<Zeroizing<String>, CryptoError> {
    if nonce_bytes.len() != 12 {
        return Err(CryptoError::InvalidNonceLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let plaintext_string =
        String::from_utf8(plaintext_bytes).map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let key = [9u8; 32];
        let secret = "secret_plaintext";
        let (encrypted, nonce) = encrypt_value(secret, &key).unwrap();
        let decrypted = decrypt_value(&encrypted, &nonce, &key).unwrap();
        assert_eq!(*decrypted, secret);
    }

    #[test]
    fn different_nonce_each_call() {
        let key = [7u8; 32];
        let secret = "same_plaintext";
        let (_, nonce1) = encrypt_value(secret, &key).unwrap();
        let (_, nonce2) = encrypt_value(secret, &key).unwrap();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let secret = "test_data";
        let (encrypted, nonce) = encrypt_value(secret, &key1).unwrap();
        let decrypt_res = decrypt_value(&encrypted, &nonce, &key2);
        assert!(decrypt_res.is_err());
    }
}

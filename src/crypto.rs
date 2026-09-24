use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| anyhow!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    Ok(key)
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce_bytes: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Cipher initialization failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed!"))
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce_bytes: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Cipher initialization failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed! Wrong password or corrupted vault."))
}

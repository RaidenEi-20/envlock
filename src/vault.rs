use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VaultData {
    pub store: HashMap<String, HashMap<String, String>>,
}

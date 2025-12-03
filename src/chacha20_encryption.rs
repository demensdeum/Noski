use crate::encryption::EncryptionLayer;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use std::error::Error;
use std::sync::Mutex;

pub struct ChaCha20Encryption {
    cipher: ChaCha20Poly1305,
    nonce_counter: Mutex<u64>,
}

impl ChaCha20Encryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        ChaCha20Encryption {
            cipher,
            nonce_counter: Mutex::new(0),
        }
    }

    pub fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let key_hex = std::env::var("ENCRYPTION_KEY")
            .map_err(|_| "ENCRYPTION_KEY not set in environment")?;
        
        let key_bytes = hex::decode(&key_hex)
            .map_err(|_| "Invalid hex in ENCRYPTION_KEY")?;
        
        if key_bytes.len() != 32 {
            return Err("ENCRYPTION_KEY must be 32 bytes (64 hex chars)".into());
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        
        Ok(Self::new(&key))
    }

    pub fn generate_key() -> [u8; 32] {
        ChaCha20Poly1305::generate_key(&mut OsRng).into()
    }

    fn get_next_nonce(&self) -> Nonce {
        let mut counter = self.nonce_counter.lock().unwrap();
        let nonce_value = *counter;
        *counter = counter.wrapping_add(1);
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&nonce_value.to_le_bytes());
        
        *Nonce::from_slice(&nonce_bytes)
    }
}

impl EncryptionLayer for ChaCha20Encryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let nonce = self.get_next_nonce();
        
        let ciphertext = self.cipher
            .encrypt(&nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if data.len() < 12 {
            return Err("Data too short for nonce".into());
        }
        
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    fn name(&self) -> &str {
        "chacha20-poly1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encryption_decryption() {
        let key = ChaCha20Encryption::generate_key();
        let encryption = ChaCha20Encryption::new(&key);
        let plaintext = b"Hello, World! This is a secret message.";
        
        let encrypted = encryption.encrypt(plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > plaintext.len());
        
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_chacha20_name() {
        let key = ChaCha20Encryption::generate_key();
        let encryption = ChaCha20Encryption::new(&key);
        assert_eq!(encryption.name(), "chacha20-poly1305");
    }
    
    #[test]
    fn test_chacha20_multiple_encryptions() {
        let key = ChaCha20Encryption::generate_key();
        let encryption = ChaCha20Encryption::new(&key);
        let plaintext = b"Test message";
        
        let encrypted1 = encryption.encrypt(plaintext).unwrap();
        let encrypted2 = encryption.encrypt(plaintext).unwrap();
        
        assert_ne!(encrypted1, encrypted2);
        
        let decrypted1 = encryption.decrypt(&encrypted1).unwrap();
        let decrypted2 = encryption.decrypt(&encrypted2).unwrap();
        
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}

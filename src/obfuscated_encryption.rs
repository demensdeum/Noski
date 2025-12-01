use crate::encryption::EncryptionLayer;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use std::error::Error;
use std::sync::Mutex;
use rand::Rng;

pub struct ObfuscatedEncryption {
    cipher: ChaCha20Poly1305,
    nonce_counter: Mutex<u64>,
}

impl ObfuscatedEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(key.into());
        ObfuscatedEncryption {
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

    fn add_tls_like_header(&self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        
        result.push(0x17);
        result.push(0x03);
        result.push(0x03);
        
        let len = data.len() as u16;
        result.extend_from_slice(&len.to_be_bytes());
        
        result.extend_from_slice(data);
        
        result
    }

    fn remove_tls_like_header(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if data.len() < 5 {
            return Err("Data too short for TLS header".into());
        }
        
        if data[0] != 0x17 || data[1] != 0x03 || data[2] != 0x03 {
            return Err("Invalid TLS-like header".into());
        }
        
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        
        if data.len() < 5 + len {
            return Err("Data length mismatch".into());
        }
        
        Ok(data[5..5+len].to_vec())
    }

    fn add_random_padding(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        
        let padding_size = rng.gen_range(8..32);
        
        let mut result = Vec::new();
        result.push(padding_size as u8);
        result.extend_from_slice(data);
        
        for _ in 0..padding_size {
            result.push(rng.gen());
        }
        
        result
    }

    fn remove_random_padding(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if data.is_empty() {
            return Err("Empty data".into());
        }
        
        let padding_size = data[0] as usize;
        
        if data.len() < 1 + padding_size {
            return Err("Invalid padding size".into());
        }
        
        let data_len = data.len() - 1 - padding_size;
        Ok(data[1..1+data_len].to_vec())
    }
}

impl EncryptionLayer for ObfuscatedEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let nonce = self.get_next_nonce();
        
        let ciphertext = self.cipher
            .encrypt(&nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        let mut encrypted = nonce.to_vec();
        encrypted.extend_from_slice(&ciphertext);
        
        let padded = self.add_random_padding(&encrypted);
        
        let obfuscated = self.add_tls_like_header(&padded);
        
        Ok(obfuscated)
    }
    
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let without_tls = self.remove_tls_like_header(data)?;
        
        let without_padding = self.remove_random_padding(&without_tls)?;
        
        if without_padding.len() < 12 {
            return Err("Data too short for nonce".into());
        }
        
        let nonce = Nonce::from_slice(&without_padding[..12]);
        let ciphertext = &without_padding[12..];
        
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    fn name(&self) -> &str {
        "obfuscated"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscated_encryption_decryption() {
        let key = ObfuscatedEncryption::generate_key();
        let encryption = ObfuscatedEncryption::new(&key);
        let plaintext = b"Hello, World! This is a secret message.";
        
        let encrypted = encryption.encrypt(plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.len() > plaintext.len());
        
        assert_eq!(encrypted[0], 0x17);
        assert_eq!(encrypted[1], 0x03);
        assert_eq!(encrypted[2], 0x03);
        
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_obfuscated_name() {
        let key = ObfuscatedEncryption::generate_key();
        let encryption = ObfuscatedEncryption::new(&key);
        assert_eq!(encryption.name(), "obfuscated");
    }
    
    #[test]
    fn test_obfuscated_multiple_encryptions() {
        let key = ObfuscatedEncryption::generate_key();
        let encryption = ObfuscatedEncryption::new(&key);
        let plaintext = b"Test message";
        
        let encrypted1 = encryption.encrypt(plaintext).unwrap();
        let encrypted2 = encryption.encrypt(plaintext).unwrap();
        
        assert_ne!(encrypted1, encrypted2);
        
        let decrypted1 = encryption.decrypt(&encrypted1).unwrap();
        let decrypted2 = encryption.decrypt(&encrypted2).unwrap();
        
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
    
    #[test]
    fn test_tls_header() {
        let key = ObfuscatedEncryption::generate_key();
        let encryption = ObfuscatedEncryption::new(&key);
        let plaintext = b"Test";
        
        let encrypted = encryption.encrypt(plaintext).unwrap();
        
        assert!(encrypted.len() >= 5);
        assert_eq!(encrypted[0], 0x17);
        assert_eq!(encrypted[1], 0x03);
        assert_eq!(encrypted[2], 0x03);
    }
}

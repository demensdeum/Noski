use crate::encryption::EncryptionLayer;
use std::error::Error;

pub struct XorEncryption {
    key: Vec<u8>,
}

impl XorEncryption {
    pub fn new(key: &[u8]) -> Self {
        if key.is_empty() {
            panic!("XOR encryption key cannot be empty");
        }
        XorEncryption {
            key: key.to_vec(),
        }
    }
    
    fn xor_transform(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ self.key[i % self.key.len()])
            .collect()
    }
}

impl EncryptionLayer for XorEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        Ok(self.xor_transform(data))
    }
    
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        Ok(self.xor_transform(data))
    }
    
    fn name(&self) -> &str {
        "xor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_encryption_decrypt() {
        let key = b"secret";
        let encryption = XorEncryption::new(key);
        let plaintext = b"Hello, World!";
        
        let encrypted = encryption.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_xor_name() {
        let encryption = XorEncryption::new(b"key");
        assert_eq!(encryption.name(), "xor");
    }
    
    #[test]
    #[should_panic(expected = "XOR encryption key cannot be empty")]
    fn test_xor_empty_key() {
        XorEncryption::new(b"");
    }
}

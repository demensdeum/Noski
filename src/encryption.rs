use std::error::Error;

pub trait EncryptionLayer: Send + Sync {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
    fn name(&self) -> &str;
}

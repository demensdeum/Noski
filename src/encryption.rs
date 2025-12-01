use tokio::io::{AsyncRead, AsyncWrite};
use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{ReadBuf};

pub trait EncryptionLayer: Send + Sync {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;
    fn name(&self) -> &str;
}

#[derive(Debug, Clone)]
pub struct PassthroughEncryption;

impl PassthroughEncryption {
    pub fn new() -> Self {
        PassthroughEncryption
    }
}

impl Default for PassthroughEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionLayer for PassthroughEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        Ok(data.to_vec())
    }
    
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        Ok(data.to_vec())
    }
    
    fn name(&self) -> &str {
        "passthrough"
    }
}

pub struct EncryptedStream<S> {
    inner: S,
    encryption: Box<dyn EncryptionLayer>,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}

impl<S> EncryptedStream<S> {
    pub fn new(stream: S, encryption: Box<dyn EncryptionLayer>) -> Self {
        EncryptedStream {
            inner: stream,
            encryption,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
        }
    }
    
    pub fn with_passthrough(stream: S) -> Self {
        Self::new(stream, Box::new(PassthroughEncryption::new()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passthrough_encryption() {
        let encryption = PassthroughEncryption::new();
        let data = b"Hello, World!";
        
        let encrypted = encryption.encrypt(data).unwrap();
        assert_eq!(encrypted, data);
        
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[test]
    fn test_passthrough_name() {
        let encryption = PassthroughEncryption::new();
        assert_eq!(encryption.name(), "passthrough");
    }
}

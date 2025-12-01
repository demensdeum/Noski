use crate::encryption::EncryptionLayer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;
use std::sync::Arc;

pub struct EncryptedReader<R> {
    inner: R,
    encryption: Arc<Box<dyn EncryptionLayer>>,
    buffer: Vec<u8>,
}

impl<R: AsyncRead + Unpin> EncryptedReader<R> {
    pub fn new(inner: R, encryption: Arc<Box<dyn EncryptionLayer>>) -> Self {
        Self {
            inner,
            encryption,
            buffer: Vec::new(),
        }
    }

    pub async fn read_encrypted(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.buffer.is_empty() {
            let copy_len = self.buffer.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&self.buffer[..copy_len]);
            self.buffer.drain(..copy_len);
            return Ok(copy_len);
        }

        let mut len_bytes = [0u8; 4];
        self.inner.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
        }

        let mut encrypted_data = vec![0u8; len];
        self.inner.read_exact(&mut encrypted_data).await?;

        let decrypted = self.encryption.decrypt(&encrypted_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let copy_len = decrypted.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&decrypted[..copy_len]);

        if decrypted.len() > copy_len {
            self.buffer.extend_from_slice(&decrypted[copy_len..]);
        }

        Ok(copy_len)
    }
}

pub struct EncryptedWriter<W> {
    inner: W,
    encryption: Arc<Box<dyn EncryptionLayer>>,
}

impl<W: AsyncWrite + Unpin> EncryptedWriter<W> {
    pub fn new(inner: W, encryption: Arc<Box<dyn EncryptionLayer>>) -> Self {
        Self {
            inner,
            encryption,
        }
    }

    pub async fn write_encrypted(&mut self, buf: &[u8]) -> io::Result<usize> {
        let encrypted = self.encryption.encrypt(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let len = encrypted.len() as u32;
        self.inner.write_all(&len.to_be_bytes()).await?;
        self.inner.write_all(&encrypted).await?;
        self.inner.flush().await?;

        Ok(buf.len())
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }
}

pub async fn copy_encrypted_to_plain<R, W>(
    reader: &mut EncryptedReader<R>,
    writer: &mut W,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buf = vec![0u8; 8192];

    loop {
        let n = match reader.read_encrypted(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }

    Ok(total)
}

pub async fn copy_plain_to_encrypted<R, W>(
    reader: &mut R,
    writer: &mut EncryptedWriter<W>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buf = vec![0u8; 8192];

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        writer.write_encrypted(&buf[..n]).await?;
        total += n as u64;
    }

    Ok(total)
}
